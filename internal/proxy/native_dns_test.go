package proxy

import (
    "bytes"
    "context"
    "encoding/binary"
    "errors"
    "io"
    "net"
    "net/http"
    "net/netip"
    "strings"
    "sync/atomic"
    "testing"
)

type roundTripFunc func(*http.Request)(*http.Response,error)
func (f roundTripFunc)RoundTrip(req *http.Request)(*http.Response,error){return f(req)}
func testDNSResponse(query []byte, ip netip.Addr) []byte {
    b:=append([]byte(nil),query...)
    binary.BigEndian.PutUint16(b[2:4],0x8180)
    if !ip.IsValid() {return b}
    binary.BigEndian.PutUint16(b[6:8],1)
    qtype:=binary.BigEndian.Uint16(b[len(b)-4:len(b)-2])
    address:=ip.AsSlice()
    header:=[]byte{0xc0,0x0c,byte(qtype>>8),byte(qtype),0,1,0,0,0,30,0,byte(len(address))}
    return append(append(b,header...),address...)
}
func TestNativeDoHFamilyPolicyAndCache(t *testing.T){
    cfg:=DefaultConfig()
    cfg.DNSStrategy="prefer_ipv6"
    r,err:=NewNativeResolver(cfg)
    if err!=nil{t.Fatal(err)}
    var queries atomic.Int32
    r.client=&http.Client{Transport:roundTripFunc(func(req *http.Request)(*http.Response,error){
        queries.Add(1)
        if req.Method!="POST" || req.Host!="cloudflare-dns.com" ||
            req.URL.Host!="1.1.1.1:443" || req.Header.Get("Content-Type")!="application/dns-message" {
            t.Errorf("bad DoH request: %v",req)
        }
        payload,err:=io.ReadAll(req.Body)
        if err!=nil{return nil,err}
        qtype:=binary.BigEndian.Uint16(payload[len(payload)-4:len(payload)-2])
        var ip netip.Addr
        if qtype==28 {ip=netip.MustParseAddr("2001:db8::42")}
        if qtype==1 {ip=netip.MustParseAddr("192.0.2.42")}
        result:=testDNSResponse(payload,ip)
        return &http.Response{StatusCode:200,Body:io.NopCloser(bytes.NewReader(result)),
            Header:http.Header{"Content-Type":[]string{"application/dns-message"}}},nil
    })}
    addresses,err:=r.LookupIP(context.Background(),"test.example")
    if err!=nil{t.Fatal(err)}
    if len(addresses)!=2 || addresses[0].String()!="2001:db8::42" || addresses[1].String()!="192.0.2.42" {
        t.Fatalf("family priority %v",addresses)
    }
    if _,err:=r.LookupIP(context.Background(),"test.example");err!=nil {t.Fatal(err)}
    if queries.Load()!=2 {t.Fatalf("cache didn't avoid repeated queries: %d",queries.Load())}
}
func TestDoHIPv4Only(t *testing.T){
    cfg:=DefaultConfig();cfg.DNSStrategy="ipv4_only"
    r,err:=NewNativeResolver(cfg);if err!=nil{t.Fatal(err)}
    var queries int
    r.client=&http.Client{Transport:roundTripFunc(func(req *http.Request)(*http.Response,error){
        queries++
        query,_:=io.ReadAll(req.Body)
        if typ:=binary.BigEndian.Uint16(query[len(query)-4:len(query)-2]);typ!=1 {t.Errorf("unexpected IPv6 query %d",typ)}
        return &http.Response{StatusCode:200,Header:http.Header{"Content-Type":[]string{"application/dns-message"}},
            Body:io.NopCloser(bytes.NewReader(testDNSResponse(query,netip.MustParseAddr("192.0.2.55"))))},nil
    })}
    addresses,err:=r.LookupIP(context.Background(),"foo.example")
    if err!=nil||len(addresses)!=1||addresses[0].String()!="192.0.2.55"||queries!=1 {
        t.Fatalf("IPv4-only failed: %v %v %d",addresses,err,queries)
    }
}
func TestMalformedDoHResponsesFailClosed(t *testing.T){
    query,id,err:=wireQuestion("secure.example",1)
    if err!=nil{t.Fatal(err)}
    for name,modify:=range map[string]func([]byte)[]byte{
        "wrong transaction":func(b []byte)[]byte{b[0]^=0x80;return b},
        "not a reply":func(b []byte)[]byte{b[2]=0;return b},
        "truncated":func(b []byte)[]byte{return b[:8]},
        "incorrect qtype":func(b []byte)[]byte{b[len(b)-4]=0x5;return b},
        "future compression ptr":func(b []byte)[]byte{b[12]=0xc0;b[13]=0x0e;return b},
        "invalid DNS status":func(b []byte)[]byte{b[3]|=3;return b},
    }{
        t.Run(name,func(t *testing.T){
            body:=modify(append([]byte(nil),query...))
            if _,err:=parseDNSAnswer(body,id,"secure.example",1);err==nil {
                t.Fatal("accepted invalid DNS reply")
            }
        })
    }
}
func TestDoHNetworkErrorDoesNotFallback(t *testing.T) {
    cfg:=DefaultConfig()
    resolver,err:=NewNativeResolver(cfg)
    if err!=nil{t.Fatal(err)}
    resolver.client=&http.Client{Transport:roundTripFunc(func(*http.Request)(*http.Response,error) {
        return nil,errors.New("offline")
    })}
    if _,err=resolver.LookupIP(context.Background(),"no-fallback.example");err==nil || !strings.Contains(err.Error(),"offline"){
        t.Fatalf("expected explicit DoH network failure, got %v",err)
    }
}
func TestPinnedBootstrapAndDNSNameValidation(t *testing.T) {
    cfg:=DefaultConfig()
    for _,address:=range []string{"127.0.0.1","192.168.1.1","10.0.0.53","169.254.2.1","::1"} {
        cfg.DNSRemote=address
        if _,err:=NewNativeResolver(cfg);err==nil{t.Errorf("accepted unsafe DoH bootstrap %s",address)}
    }
    for _,host:=range []string{"","bad..example","bad_label.example","-bad.example",strings.Repeat("a",64)+".com"}{
        if err:=validDNSName(host);err==nil {t.Errorf("accepted malformed hostname %q",host)}
    }
    if _,err:=netip.ParseAddr("203.0.113.1");err!=nil {t.Fatal(err)}
    _=net.JoinHostPort("::1","443")
}

func TestNativeTCPDirectActuallyUsesDoH(t *testing.T) {
    echo := echoServer(t)
    _,port,err:=net.SplitHostPort(echo.Addr().String())
    if err!=nil{t.Fatal(err)}
    cfg:=DefaultConfig()
    cfg.DNSStrategy="ipv4_only"
    srv,err:=NewWithConfig(cfg)
    if err!=nil{t.Fatal(err)}
    var queries atomic.Int32
    srv.resolver.client=&http.Client{Transport:roundTripFunc(func(req *http.Request)(*http.Response,error){
        queries.Add(1)
        query,_:=io.ReadAll(req.Body)
        return &http.Response{
            StatusCode:200,
            Header:http.Header{"Content-Type":[]string{"application/dns-message"}},
            Body:io.NopCloser(bytes.NewReader(testDNSResponse(query,netip.MustParseAddr("127.0.0.1")))),
        },nil
    })}
    conn,err:=srv.dialTarget("private-target.example",port)
    if err!=nil {t.Fatal(err)}
    defer conn.Close()
    _,err=conn.Write([]byte("eproxy-native-dns"))
    if err!=nil{t.Fatal(err)}
    result:=make([]byte,len("eproxy-native-dns"))
    _,err=io.ReadFull(conn,result)
    if err!=nil || string(result)!="eproxy-native-dns" {
        t.Fatalf("incorrect eproxy native relay %q %v",result,err)
    }
    if queries.Load()!=1 {t.Fatalf("expected one encrypted DNS query, got %d",queries.Load())}
}

func TestNativeProxyServerBootstrapUsesPinnedDoH(t *testing.T) {
    upstream:=echoServer(t)
    _,port,err:=net.SplitHostPort(upstream.Addr().String())
    if err!=nil{t.Fatal(err)}
    cfg:=DefaultConfig();cfg.DNSStrategy="ipv4_only"
    resolver,err:=NewNativeResolver(cfg)
    if err!=nil{t.Fatal(err)}
    var count atomic.Int32
    resolver.client=&http.Client{Transport:roundTripFunc(func(req *http.Request)(*http.Response,error){
        count.Add(1)
        wire,_:=io.ReadAll(req.Body)
        return &http.Response{
            StatusCode:200,
            Header:http.Header{"Content-Type":[]string{"application/dns-message"}},
            Body:io.NopCloser(bytes.NewReader(testDNSResponse(wire,netip.MustParseAddr("127.0.0.1")))),
        },nil
    })}
    ctx:=context.WithValue(context.Background(),dohDialerContextKey{},resolver)
    conn,err:=dialUpstream(ctx,net.JoinHostPort("proxy-bootstrap.example",port))
    if err!=nil{t.Fatal(err)}
    defer conn.Close()
    _,_=conn.Write([]byte("upstream"))
    got:=make([]byte,len("upstream"))
    _,err=io.ReadFull(conn,got)
    if err!=nil || string(got)!="upstream" || count.Load()!=1 {
        t.Fatalf("upstream secure bootstrap %q %v; DoH calls %d",got,err,count.Load())
    }
}
