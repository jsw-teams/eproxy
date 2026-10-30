package proxy

import (
 "encoding/base64"
 "testing"
)

func TestURIProviderImports(t *testing.T) {
 lines := "trojan://secret@trojan.example:443?sni=trojan.example#t1\n"+
  "vless://4e52614c-1e02-4527-9254-f6e8beeb53e8@v.example:443?security=reality&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sni=www.example.com#v1\n"+
  "hysteria2://password@hy.example:443?sni=hy.example#h1\n"
 for _,data:=range []string{lines,base64.StdEncoding.EncodeToString([]byte(lines))} {
  nodes,err:=parseSubscription("demo",[]byte(data))
  if err!=nil {t.Fatal(err)}
  if len(nodes)!=3 {t.Fatalf("expected 3 nodes got %d",len(nodes))}
  if nodes[0]["tag"]!="sub_demo_t1" || nodes[0]["type"]!="trojan" {t.Fatal("wrong Trojan URI parse")}
  if nodes[1]["tag"]!="sub_demo_v1" || nodes[1]["type"]!="vless" {t.Fatal("wrong VLESS URI parse")}
  if nodes[2]["tag"]!="sub_demo_h1" || nodes[2]["type"]!="hysteria2" {t.Fatal("wrong Hysteria2 URI parse")}
  tls:=nodes[1]["tls"].(map[string]interface{})
  if tls["reality"]==nil || tls["utls"]==nil {t.Fatal("VLESS REALITY details missing")}
 }
}
func TestSubscriptionRejectsDangerousURIs(t *testing.T) {
 cases:=[]string{
  "file:///etc/shadow",
  "vless://uuid@v.example:443?security=none#x",
  "trojan://secret@t.example:443?insecure=true",
  "hysteria2://secret@localhost:0",
 }
 for _,uri:=range cases {
  if _,err:=parseSubscription("demo",[]byte(uri));err==nil {t.Fatalf("accepted invalid URI: %s",uri)}
 }
}
