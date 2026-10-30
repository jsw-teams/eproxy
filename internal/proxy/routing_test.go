package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPForwardProxy(t *testing.T) {
	server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.Header.Get("Proxy-Authorization")!="" {t.Error("proxy credentials reached origin")}
		_,_=io.WriteString(w,"origin-response")
	}))
	defer server.Close()
	proxy:=proxyServer(t)
	c,err:=net.Dial("tcp",proxy.Addr().String())
	if err!=nil{t.Fatal(err)}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4*time.Second))
	target:=server.URL
	_,err=io.WriteString(c,"GET "+target+"/hello HTTP/1.1\r\nHost: "+strings.TrimPrefix(target,"http://")+"\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\nConnection: close\r\n\r\n")
	if err!=nil{t.Fatal(err)}
	reply,err:=io.ReadAll(c)
	if err!=nil{t.Fatal(err)}
	if !strings.Contains(string(reply),"200 OK") || !strings.Contains(string(reply),"origin-response"){t.Fatalf("HTTP forwarding failed: %s",reply)}
}

func TestRouteBlockHTTPConnect(t *testing.T) {
	cfg:=DefaultConfig()
	cfg.Rules=[]Rule{{DomainSuffix:"blocked.example",Outbound:"block"}}
	s,err:=NewWithConfig(cfg)
	if err!=nil{t.Fatal(err)}
	ln,err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil{t.Fatal(err)}
	defer ln.Close()
	go func(){_ = s.Serve(ln)}()
	c,err:=net.Dial("tcp",ln.Addr().String())
	if err!=nil{t.Fatal(err)}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3*time.Second))
	_,_=io.WriteString(c,"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
	line,err:=bufio.NewReader(c).ReadString('\n')
	if err!=nil || !strings.Contains(line,"403 Forbidden"){t.Fatalf("expected 403, got %q %v",line,err)}
}

func TestSOCKS5AuthenticatedOutbound(t *testing.T) {
	echo:=echoServer(t)
	cfg:=DefaultConfig()
	cfg.Username="user"
	cfg.Password="secret"
	s,err:=NewWithConfig(cfg)
	if err!=nil{t.Fatal(err)}
	ln,err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil{t.Fatal(err)}
	defer ln.Close()
	go func(){_ = s.Serve(ln)}()
	ctx,cancel:=context.WithTimeout(context.Background(),4*time.Second)
	defer cancel()
	c,err:=dialSocks(ctx,Outbound{Type:"socks5",Address:ln.Addr().String(),Username:"user",Password:"secret"},echo.Addr().String())
	if err!=nil{t.Fatal(err)}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3*time.Second))
	_,_=c.Write([]byte("socks5-auth-ok"))
	b:=make([]byte,len("socks5-auth-ok"))
	_,err=io.ReadFull(c,b)
	if err!=nil || string(b)!="socks5-auth-ok" {t.Fatalf("SOCKS5 authentication relay %q %v",b,err)}
}
