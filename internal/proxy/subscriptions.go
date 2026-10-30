package proxy

import (
 "context"
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
  nodes,err:=validateProvider(subscription.Name,limited)
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
