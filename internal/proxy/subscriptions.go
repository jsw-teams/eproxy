package proxy

import (
 "context"
 "encoding/base64"
 "strconv"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "os"
 "regexp"
 "strings"
 "time"
)

var providerTag = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,48}$`)

// ProviderSnapshot stores only outbounds from a remote provider. It does not
// import routes, inbounds, DNS, scripts or firewall changes.
type ProviderSnapshot struct {
 Outbounds []map[string]interface{} `json:"outbounds"`
}

var providerTypes = map[string]bool{
 "hysteria2":true,"vless":true,"trojan":true,"shadowsocks":true,
 "socks":true,"http":true,"tuic":true,"vmess":true,
}

// validateProvider checks the returned data rather than executing third-party
// configuration wholesale. Never print provider credentials.
func validateProvider(name string, body []byte) ([]map[string]interface{},error) {
 var obj map[string]json.RawMessage
 if err:=json.Unmarshal(body,&obj);err!=nil{return nil,err}
 if len(obj)!=1 {return nil,errors.New("subscription must contain only outbounds")}
 raw,ok:=obj["outbounds"]
 if !ok{return nil,errors.New("subscription has no outbounds")}
 var out []map[string]interface{}
 if err:=json.Unmarshal(raw,&out);err!=nil{return nil,err}
 if len(out)>128{return nil,errors.New("too many subscription nodes")}
 for _,node:=range out {
  tag,_:=node["tag"].(string)
  typ,_:=node["type"].(string)
  if !providerTag.MatchString(tag)|| !providerTypes[typ] {return nil,errors.New("invalid or unsupported subscription node")}
  node["tag"]="sub_"+name+"_"+tag
  if _,ok:=node["server"].(string);!ok {return nil,errors.New("subscription node lacks server")}
  port,ok:=node["server_port"].(float64)
  if !ok || port<1 || port>65535 || port!=float64(int(port)){return nil,errors.New("invalid subscription port")}
  if tlsCfg,ok:=node["tls"].(map[string]interface{});ok {
   if insecure,ok:=tlsCfg["insecure"].(bool);ok && insecure{return nil,errors.New("subscription cannot disable TLS verification")}
  }
 }
 return out,nil
}
func secureSubscriptionClient() *http.Client {
 transport:=&http.Transport{TLSHandshakeTimeout:8*time.Second,ResponseHeaderTimeout:8*time.Second}
 transport.DialContext=func(ctx context.Context,network,address string)(net.Conn,error) {
  host,port,err:=net.SplitHostPort(address)
  if err!=nil{return nil,err}
  if port!="443" {return nil,errors.New("subscription must use HTTPS port 443")}
  ips,err:=net.DefaultResolver.LookupIPAddr(ctx,host)
  if err!=nil{return nil,err}
  for _,a:=range ips {
   ip:=a.IP
   if ip.IsPrivate()||ip.IsLoopback()||ip.IsLinkLocalUnicast()||ip.IsUnspecified()||ip.IsMulticast() || !ip.IsGlobalUnicast() {
    return nil,errors.New("subscription resolved to disallowed address")
   }
  }
  if len(ips)==0{return nil,errors.New("subscription DNS returned no address")}
  return (&net.Dialer{Timeout:8*time.Second}).DialContext(ctx,network,net.JoinHostPort(ips[0].IP.String(),port))
 }
 return &http.Client{Timeout:15*time.Second,Transport:transport,CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}}
}
func SyncSubscriptions(cfg Config, dest string) error {
 if cfg.Engine!="singbox" {return errors.New("subscription sync requires singbox mode")}
 client:=secureSubscriptionClient()
 all:=make([]map[string]interface{},0)
 for _,subscription:=range cfg.Subscriptions {
  if !providerTag.MatchString(subscription.Name){return errors.New("invalid provider name")}
  u,err:=url.Parse(subscription.URL)
  if err!=nil || u.Scheme!="https" || u.User!=nil || u.Port()!="" {return errors.New("subscription URL must use HTTPS default port")}
  req,err:=http.NewRequest(http.MethodGet,subscription.URL,nil)
  if err!=nil{return err}
  req.Header.Set("User-Agent","eproxy-provider/0.3")
  resp,err:=client.Do(req)
  if err!=nil{return fmt.Errorf("provider %s download failed: %w",subscription.Name,err)}
  if resp.StatusCode!=200 {resp.Body.Close();return fmt.Errorf("provider %s returned HTTP %d",subscription.Name,resp.StatusCode)}
  limited,err:=io.ReadAll(io.LimitReader(resp.Body,1024*1024+1))
  resp.Body.Close()
  if err!=nil{return err}
  if len(limited)>1024*1024{return errors.New("subscription exceeds 1 MiB")}
  nodes,err:=parseSubscription(subscription.Name,limited)
  if err!=nil{return fmt.Errorf("invalid provider %s: %w",subscription.Name,err)}
  all=append(all,nodes...)
 }
 if len(all)>256{return errors.New("aggregate provider node limit exceeded")}
 data,err:=json.Marshal(ProviderSnapshot{Outbounds:all})
 if err!=nil{return err}
 return writePrivate(dest,data)
}
func ReadProviders(path string)(ProviderSnapshot,error) {
 var p ProviderSnapshot
 raw,err:=os.ReadFile(path)
 if err!=nil {if errors.Is(err,os.ErrNotExist){return p,nil};return p,err}
 if len(raw)>2*1024*1024{return p,errors.New("provider cache too large")}
 if err=json.Unmarshal(raw,&p);err!=nil{return p,err}
 for _,node:=range p.Outbounds {
  tag,_:=node["tag"].(string)
  if !strings.HasPrefix(tag,"sub_")|| !providerTag.MatchString(tag) {return p,errors.New("invalid cached provider tag")}
 }
 return p,nil
}

func parseSubscription(name string, body []byte)([]map[string]interface{},error){
 trimmed:=strings.TrimSpace(string(body))
 if strings.HasPrefix(trimmed,"{") {
  return validateProvider(name,body)
 }
 if strings.Index(trimmed,"://")<0 {
  decoded,err:=base64.StdEncoding.DecodeString(strings.Join(strings.Fields(trimmed),""))
  if err!=nil {
   decoded,err=base64.RawStdEncoding.DecodeString(strings.Join(strings.Fields(trimmed),""))
   if err!=nil {return nil,errors.New("provider is neither JSON nor valid base64 URI list")}
  }
  trimmed=string(decoded)
 }
 lines:=strings.Split(strings.ReplaceAll(trimmed,"\r",""),"\n")
 nodes:=make([]map[string]interface{},0)
 for i,line:=range lines {
  line=strings.TrimSpace(line)
  if line=="" || strings.HasPrefix(line,"#") {continue}
  if len(nodes)>=128{return nil,errors.New("too many URI nodes")}
  node,err:=parseNodeURI(line,i)
  if err!=nil{return nil,fmt.Errorf("provider %s node %d: %w",name,i+1,err)}
  node["tag"]="sub_"+name+"_"+node["tag"].(string)
  nodes=append(nodes,node)
 }
 if len(nodes)==0 {return nil,errors.New("subscription contained no supported nodes")}
 return nodes,nil
}
func parseNodeURI(line string,index int)(map[string]interface{},error){
 u,err:=url.Parse(line)
 if err!=nil || u.User==nil || u.Hostname()=="" || u.Port()=="" {return nil,errors.New("invalid node URI")}
 tag:=u.Fragment
 if tag==""{tag=fmt.Sprintf("node%d",index+1)}
 var b strings.Builder
 for _,r:=range tag {
  if (r>='A'&&r<='Z')||(r>='a'&&r<='z')||(r>='0'&&r<='9')||r=='-'||r=='_' {b.WriteRune(r)}else{b.WriteRune('_')}
 }
 tag=b.String()
 if len(tag)>48 {tag=tag[:48]}
 if !providerTag.MatchString(tag){return nil,errors.New("invalid node tag")}
 port,err:=strconv.Atoi(u.Port())
 if err!=nil || port<=0 || port>65535{return nil,errors.New("invalid node port")}
 node:=map[string]interface{}{"tag":tag,"server":u.Hostname(),"server_port":port}
 sni:=u.Query().Get("sni")
 if sni==""{sni=u.Hostname()}
 if u.Query().Get("allowInsecure")=="1" || u.Query().Get("insecure")=="true" {
  return nil,errors.New("insecure TLS settings are forbidden")
 }
 tls:=map[string]interface{}{"enabled":true,"server_name":sni}
 switch u.Scheme {
 case "trojan":
  node["type"]="trojan";node["password"]=u.User.Username();node["tls"]=tls
 case "vless":
  node["type"]="vless";node["uuid"]=u.User.Username();node["tls"]=tls
  if u.Query().Get("security")=="reality" {
   pub:=u.Query().Get("pbk")
   if pub==""{return nil,errors.New("REALITY public key missing")}
   tls["reality"]=map[string]interface{}{"enabled":true,"public_key":pub,"short_id":u.Query().Get("sid")}
   tls["utls"]=map[string]interface{}{"enabled":true,"fingerprint":"chrome"}
  }else if v:=u.Query().Get("security");v!=""&&v!="tls" {
   return nil,errors.New("unsupported VLESS security")
  }
 case "hysteria2","hy2":
  node["type"]="hysteria2";node["password"]=u.User.Username();node["tls"]=tls
  if u.Query().Get("obfs")=="salamander" {
   node["obfs"]=map[string]interface{}{"type":"salamander","password":u.Query().Get("obfs-password")}
  }
 case "ss":
  node["type"]="shadowsocks"
  user:=u.User.Username()
  pass,ok:=u.User.Password()
  if !ok {
   pair,err:=base64.RawURLEncoding.DecodeString(user)
   if err!=nil {pair,err=base64.StdEncoding.DecodeString(user);if err!=nil{return nil,errors.New("invalid Shadowsocks userinfo")}}
   parts:=strings.SplitN(string(pair),":",2)
   if len(parts)!=2{return nil,errors.New("invalid Shadowsocks method/key")}
   user,pass=parts[0],parts[1]
  }
  node["method"]=user;node["password"]=pass
 default: return nil,errors.New("unsupported node URI protocol")
 }
 if u.User.Username()==""{return nil,errors.New("missing node credential")}
 return node,nil
}
