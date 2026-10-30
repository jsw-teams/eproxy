package proxy

import (
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
 "strings"
)

func TestSingBoxAdvancedProtocolAndTunConfig(t *testing.T){
 c:=DefaultConfig()
 c.Engine="singbox"
 c.EnableTUN=true
 c.TUNInterface="br-lan"
 c.DNSStrategy="prefer_ipv6"
 c.DNSRemote="2606:4700:4700::1111"
 c.Outbounds=map[string]Outbound{
  "direct":{Type:"direct"},
  "hy2":{Type:"hysteria2",Address:"hy.example:443",ServerName:"hy.example",Password:"sample"},
  "reality":{Type:"vless-reality",Address:"v.example:443",ServerName:"v.example",UUID:"4e52614c-1e02-4527-9254-f6e8beeb53e8",RealityPublicKey:"example-public-key",RealityShortID:"01"},
  "ss22":{Type:"shadowsocks-2022",Address:"ss.example:443",Method:"2022-blake3-aes-256-gcm",Password:"example-base64-key"},
 }
 c.Rules=[]Rule{{DomainSuffix:"blocked.example",Outbound:"block"},{DomainSuffix:"proxy.example",Outbound:"hy2"}}
 if err:=c.Validate();err!=nil {t.Fatal(err)}
 raw,err:=SingBoxDocument(c)
 if err!=nil {t.Fatal(err)}
 var doc map[string]interface{}
 if err=json.Unmarshal(raw,&doc);err!=nil {t.Fatal(err)}
 inbound:=doc["inbounds"].([]interface{})
 if len(inbound)!=2 {t.Fatalf("expected mixed and TUN, got %d",len(inbound))}
 tun:=inbound[1].(map[string]interface{})
 if tun["auto_route"]!=true || tun["auto_redirect"]!=true || tun["strict_route"]!=true {t.Fatal("TUN safeguards missing")}
 if tun["include_interface"].([]interface{})[0]!="br-lan" {t.Fatal("TUN should only intercept br-lan")}
 dns:=doc["dns"].(map[string]interface{})
 if dns["strategy"]!="prefer_ipv6" {t.Fatal("IPv6 preference not exported")}
 ob:=doc["outbounds"].([]interface{})
 protocols:=map[string]map[string]interface{}{}
 for _,n:=range ob{v:=n.(map[string]interface{});protocols[v["tag"].(string)]=v}
 for _,key:=range []string{"hy2","reality","ss22"}{if protocols[key]==nil {t.Fatalf("missing outbound %s",key)}}
 if protocols["hy2"]["type"]!="hysteria2" || protocols["ss22"]["method"]!="2022-blake3-aes-256-gcm" {t.Fatal("wrong sing-box protocol mapping")}
 reality:=protocols["reality"]["tls"].(map[string]interface{})["reality"].(map[string]interface{})
 if reality["enabled"]!=true {t.Fatal("REALITY not exported")}
 route:=doc["route"].(map[string]interface{})
 rules:=route["rules"].([]interface{})
 if len(rules)<3 {t.Fatal("missing DNS and domain routing rules")}
}

func TestAdvancedUnsupportedInNativeAndUnsafeTUNRejected(t *testing.T){
 cfg:=DefaultConfig()
 cfg.Outbounds["h"] = Outbound{Type:"hysteria2",Address:"hy.example:443",Password:"p",ServerName:"hy.example"}
 if cfg.Validate()==nil {t.Fatal("native must not claim Hysteria2")}
 cfg.Engine="singbox";cfg.EnableTUN=true;cfg.TUNInterface="eth0"
 if cfg.Validate()==nil {t.Fatal("unsafe TUN interception accepted")}
 cfg.TUNInterface="br-lan";if err:=cfg.Validate();err!=nil {t.Fatal(err)}
}

func TestProviderSchemaAndPrivateCache(t *testing.T){
 bad:=[]string{
  `{"outbounds":[{"type":"direct","tag":"x"}]}`,
  `{"outbounds":[{"type":"trojan","tag":"x","server":"a","server_port":443,"tls":{"insecure":true}}]}`,
  `{"outbounds":[],"route":{"final":"attack"}}`,
 }
 for _,item:=range bad {if _,err:=validateProvider("provider",[]byte(item));err==nil{t.Fatalf("accepted unsafe provider %s",item)}}
 raw:=[]byte(`{"outbounds":[{"type":"hysteria2","tag":"node","server":"hy.example","server_port":443,"password":"secret","tls":{"enabled":true,"server_name":"hy.example"}}]}`)
 nodes,err:=validateProvider("provider",raw)
 if err!=nil{t.Fatal(err)}
 if nodes[0]["tag"]!="sub_provider_node"{t.Fatal("provider namespace not applied")}
 tmp:=t.TempDir()
 cache:=filepath.Join(tmp,"nodes.json")
 snap,_:=json.Marshal(ProviderSnapshot{Outbounds:nodes})
 if err:=writePrivate(cache,snap);err!=nil {t.Fatal(err)}
 info,err:=os.Stat(cache)
 if err!=nil || info.Mode().Perm()!=0600 {t.Fatalf("private cache permissions: %v %v",info,err)}
 c:=DefaultConfig();c.Engine="singbox"
 path:=filepath.Join(tmp,"runtime.json")
 if err:=WriteSingBoxConfig(path,c,cache);err!=nil{t.Fatal(err)}
 data,err:=os.ReadFile(path)
 if err!=nil || !strings.Contains(string(data),"sub_provider_node"){t.Fatal("provider missing from generated config")}
}
