package proxy

// Native DNS-over-HTTPS (RFC 8484) resolver for eproxy direct traffic.
// Wire encoding and answer validation are original and kept independent of
// other proxy engines. TLS is verified and the DoH server IP is preconfigured:
// no system resolver is used to bootstrap the DNS service.
import (
    "bytes"
    "context"
    "crypto/rand"
    "crypto/tls"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/netip"
    "strings"
    "sync"
    "time"
)

type dnsEntry struct {
    addresses []netip.Addr
    expires time.Time
}
type NativeResolver struct {
    client *http.Client
    url, name, strategy string
    mu sync.Mutex
    cache map[string]dnsEntry
}

// NewNativeResolver sets a pinned-IP transport; HTTPS certificates must match
// cfg.DNSServerName. Requests never follow redirects or fall back to UDP/53.
func NewNativeResolver(cfg Config) (*NativeResolver, error) {
    ip,err:=netip.ParseAddr(cfg.DNSRemote)
    if err!=nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
        return nil,errors.New("DNS bootstrap IP must be a public unicast address")
    }
    if err:=validDNSName(strings.ToLower(cfg.DNSServerName));err!=nil {
        return nil,fmt.Errorf("DNS TLS server name: %w",err)
    }
    dial:= &net.Dialer{Timeout:6*time.Second}
    transport:= &http.Transport{
        TLSClientConfig:&tls.Config{ServerName:cfg.DNSServerName,MinVersion:tls.VersionTLS12},
        DialContext:func(ctx context.Context, network, _ string)(net.Conn,error){
            return dial.DialContext(ctx,"tcp",net.JoinHostPort(ip.String(),"443"))
        },
        DisableKeepAlives:false,
        MaxIdleConnsPerHost:2,
        TLSHandshakeTimeout:6*time.Second,
        ResponseHeaderTimeout:6*time.Second,
        ForceAttemptHTTP2:true,
    }
    return &NativeResolver{
        client:&http.Client{Transport:transport,Timeout:8*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}},
        url:"https://"+net.JoinHostPort(ip.String(),"443")+"/dns-query",
        name:cfg.DNSServerName, strategy:cfg.DNSStrategy,
        cache:make(map[string]dnsEntry),
    },nil
}

// LookupIP is intentionally fail-closed. No fallback to local/system DNS if
// the configured DoH server is unavailable or returns malformed answers.
func (r *NativeResolver) LookupIP(ctx context.Context,host string)([]netip.Addr,error){
    if ip,err:=netip.ParseAddr(host);err==nil{return []netip.Addr{ip},nil}
    host=strings.TrimSuffix(strings.ToLower(host),".")
    if err:=validDNSName(host);err!=nil{return nil,err}
    r.mu.Lock()
    if v,ok:=r.cache[host];ok && time.Now().Before(v.expires) {
        out:=append([]netip.Addr(nil),v.addresses...)
        r.mu.Unlock()
        return out,nil
    }
    r.mu.Unlock()
    // Query both families to allow a reliable fallback for prefer_* strategies.
    types:=[]uint16{1,28}
    if r.strategy=="prefer_ipv6" || r.strategy=="ipv6_only" {types=[]uint16{28,1}}
    if r.strategy=="ipv4_only" {types=[]uint16{1}}
    if r.strategy=="ipv6_only" {types=[]uint16{28}}
    var results []netip.Addr
    for _,qtype:=range types {
        ips,err:=r.query(ctx,host,qtype)
        if err!=nil {return nil,err}
        results=append(results,ips...)
    }
    if len(results)==0 {return nil,fmt.Errorf("no DNS records matching %s strategy",r.strategy)}
    r.mu.Lock()
    if len(r.cache)>2048 {r.cache=make(map[string]dnsEntry)}
    r.cache[host]=dnsEntry{addresses:append([]netip.Addr(nil),results...),expires:time.Now().Add(45*time.Second)}
    r.mu.Unlock()
    return results,nil
}

func validDNSName(name string)error{
    if len(name)==0 || len(name)>253{return errors.New("invalid DNS name length")}
    for _,label:=range strings.Split(name,"."){
        if len(label)==0 || len(label)>63 || label[0]=='-' || label[len(label)-1]=='-' {
            return errors.New("invalid DNS label")
        }
        for _,c:=range label {
            if !((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-') {
                return errors.New("DNS name must be ASCII DNS labels (use punycode for IDNs)")
            }
        }
    }
    return nil
}
func wireQuestion(host string,qtype uint16)([]byte,uint16,error){
    if err:=validDNSName(host);err!=nil{return nil,0,err}
    buf:=make([]byte,12)
    if _,err:=rand.Read(buf[:2]);err!=nil{return nil,0,err}
    binary.BigEndian.PutUint16(buf[2:],0x0100) // recursion desired
    binary.BigEndian.PutUint16(buf[4:],1)
    for _,label:=range strings.Split(host,"."){
        buf=append(buf,byte(len(label)))
        buf=append(buf,label...)
    }
    buf=append(buf,0,byte(qtype>>8),byte(qtype),0,1)
    return buf,binary.BigEndian.Uint16(buf[:2]),nil
}
func (r *NativeResolver) query(ctx context.Context,host string,qtype uint16)([]netip.Addr,error){
    wire,id,err:=wireQuestion(host,qtype)
    if err!=nil{return nil,err}
    req,err:=http.NewRequestWithContext(ctx,http.MethodPost,r.url,bytes.NewReader(wire))
    if err!=nil{return nil,err}
    req.Host=r.name
    req.Header.Set("Content-Type","application/dns-message")
    req.Header.Set("Accept","application/dns-message")
    resp,err:=r.client.Do(req)
    if err!=nil{return nil,fmt.Errorf("secure DNS query failed: %w",err)}
    defer resp.Body.Close()
    if resp.StatusCode!=200{return nil,fmt.Errorf("DoH HTTP status %d",resp.StatusCode)}
    if ct:=resp.Header.Get("Content-Type");!strings.HasPrefix(strings.ToLower(ct),"application/dns-message"){
        return nil,errors.New("invalid DoH content type")
    }
    body,err:=io.ReadAll(io.LimitReader(resp.Body,65536))
    if err!=nil{return nil,err}
    if len(body)>65535{return nil,errors.New("oversized DNS response")}
    return parseDNSAnswer(body,id,host,qtype)
}
// wireName handles compression pointers and rejects loops, invalid labels and
// out-of-bounds offsets. Returned next offset follows the uncompressed header.
func wireName(msg []byte,off int,depth int)(string,int,error){
    if depth>12{return "",0,errors.New("DNS compression recursion limit")}
    labels:=make([]string,0,8)
    current:=off
    jumped:=false
    next:=off
    for steps:=0;steps<128;steps++ {
        if current>=len(msg){return "",0,io.ErrUnexpectedEOF}
        b:=msg[current]
        if b&0xc0==0xc0 {
            if current+1>=len(msg){return "",0,io.ErrUnexpectedEOF}
            ptr:=int(b&0x3f)<<8|int(msg[current+1])
            if ptr>=len(msg) || ptr>=current {return "",0,errors.New("invalid DNS compression pointer")}
            if !jumped {next=current+2;jumped=true}
            sub,_,err:=wireName(msg,ptr,depth+1)
            if err!=nil{return "",0,err}
            if sub!="" {labels=append(labels,sub)}
            return strings.Join(labels,"."),next,nil
        }
        if b&0xc0!=0{return "",0,errors.New("invalid DNS label prefix")}
        current++
        if b==0 {
            if !jumped{next=current}
            return strings.Join(labels,"."),next,nil
        }
        if b>63 || current+int(b)>len(msg){return "",0,io.ErrUnexpectedEOF}
        labels=append(labels,strings.ToLower(string(msg[current:current+int(b)])))
        current+=int(b)
    }
    return "",0,errors.New("DNS labels exceed limit")
}
func parseDNSAnswer(msg []byte,id uint16,host string,qtype uint16)([]netip.Addr,error){
    if len(msg)<12{return nil,io.ErrUnexpectedEOF}
    if binary.BigEndian.Uint16(msg[:2])!=id{return nil,errors.New("mismatched DNS transaction ID")}
    flags:=binary.BigEndian.Uint16(msg[2:4])
    if flags&0x8000==0 || flags&0x0200!=0 || flags&0x000f!=0 {
        return nil,errors.New("invalid, truncated or failed DNS response")
    }
    qd:=int(binary.BigEndian.Uint16(msg[4:6]))
    an:=int(binary.BigEndian.Uint16(msg[6:8]))
    if qd!=1 || an>128{return nil,errors.New("invalid DNS response counts")}
    name,off,err:=wireName(msg,12,0)
    if err!=nil{return nil,err}
    if name!=host || off+4>len(msg) || binary.BigEndian.Uint16(msg[off:off+2])!=qtype || binary.BigEndian.Uint16(msg[off+2:off+4])!=1 {
        return nil,errors.New("DNS question did not match query")
    }
    off+=4
    type answer struct{name string; typ uint16; alias string; ip netip.Addr}
    list:=make([]answer,0,an)
    for i:=0;i<an;i++{
        owner,at,err:=wireName(msg,off,0)
        if err!=nil{return nil,err}
        if at+10>len(msg){return nil,io.ErrUnexpectedEOF}
        typ:=binary.BigEndian.Uint16(msg[at:at+2])
        cls:=binary.BigEndian.Uint16(msg[at+2:at+4])
        size:=int(binary.BigEndian.Uint16(msg[at+8:at+10]))
        data:=at+10
        if data+size>len(msg){return nil,io.ErrUnexpectedEOF}
        a:=answer{name:owner,typ:typ}
        if cls==1 {
            if typ==5 {
                alias,end,err:=wireName(msg,data,0)
                if err!=nil || end>data+size{return nil,errors.New("malformed CNAME")}
                a.alias=alias
            } else if (typ==1 && size==4)||(typ==28 && size==16) {
                a.ip,_=netip.AddrFromSlice(msg[data:data+size])
            }
            list=append(list,a)
        }
        off=data+size
    }
    allowed:=map[string]bool{host:true}
    for i:=0;i<8;i++{
        added:=false
        for _,a:=range list {
            if a.typ==5 && allowed[a.name] && !allowed[a.alias] && a.alias!=""{
                allowed[a.alias]=true;added=true
            }
        }
        if !added{break}
    }
    ips:=make([]netip.Addr,0,4)
    for _,a:=range list {
        if a.typ==qtype && a.ip.IsValid() && allowed[a.name] {
            ips=append(ips,a.ip)
        }
    }
    return ips,nil
}
