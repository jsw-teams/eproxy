package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigValidationAndRouting(t *testing.T) {
	cfg:=DefaultConfig()
	if err:=cfg.Validate();err!=nil {t.Fatal(err)}
	cfg.Listen="0.0.0.0:1080"
	if err:=cfg.Validate();err==nil {t.Fatal("public no-auth listener accepted")}
	cfg.Listen="127.0.0.1:1080"
	cfg.Username="alice"
	if err:=cfg.Validate();err==nil {t.Fatal("unpaired credentials accepted")}
	cfg.Password="secret"
	cfg.Outbounds["remote"]=Outbound{Type:"trojan",Address:"127.0.0.1:443",ServerName:"localhost",Password:"password"}
	cfg.Rules=[]Rule{{DomainSuffix:"blocked.example",Outbound:"block"},{DomainSuffix:"proxy.example",Outbound:"remote"}}
	if err:=cfg.Validate();err!=nil{t.Fatal(err)}
	for _,v:=range []struct{host,typ string; blocked bool}{
		{"sub.blocked.example","",true},
		{"proxy.example","trojan",false},
		{"sub.proxy.example","trojan",false},
		{"evilproxy.example","direct",false},
	} {
		ob,block:=cfg.OutboundFor(v.host)
		if block!=v.blocked || (!block && ob.Type!=v.typ) {t.Errorf("route %v got %v %t",v,ob.Type,block)}
	}
	cfg.Outbounds["bad"]=Outbound{Type:"http",Address:"some.example:8080",Username:"u",Password:"secret"}
	if err:=cfg.Validate();err==nil {t.Fatal("plaintext credentials leaked to remote HTTP proxy")}
}

func TestJSONRejectsUnknownKeys(t *testing.T) {
	p:=filepath.Join(t.TempDir(),"config.json")
	if err:=os.WriteFile(p,[]byte(`{"listen":"127.0.0.1:1080","wat":true}`),0600);err!=nil{t.Fatal(err)}
	if _,err:=LoadConfig(p);err==nil{t.Fatal("unknown config key accepted")}
}

func TestHTTPBasicClientAuth(t *testing.T) {
	cfg:=DefaultConfig()
	cfg.Username="user";cfg.Password="pass"
	s,err:=NewWithConfig(cfg)
	if err!=nil {t.Fatal(err)}
	ln,err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil {t.Fatal(err)}
	go func(){_ = s.Serve(ln)}()
	t.Cleanup(func(){_ = ln.Close()})
	for _,v:=range []struct{header,expected string}{
		{"","407"},
		{"Proxy-Authorization: Basic dXNlcjpiYWQ=\r\n","407"},
		{"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n","502"},
	} {
		c,err:=net.Dial("tcp",ln.Addr().String())
		if err!=nil{t.Fatal(err)}
		_ = c.SetDeadline(time.Now().Add(3*time.Second))
		_,_ = io.WriteString(c,"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n"+v.header+"\r\n")
		status,err:=bufio.NewReader(c).ReadString('\n')
		_ = c.Close()
		if err!=nil || !strings.Contains(status,v.expected) {t.Errorf("got %q err %v, expected %s",status,err,v.expected)}
	}
}

func TestSOCKS5InboundPasswordAuth(t *testing.T) {
	cfg:=DefaultConfig();cfg.Username="user";cfg.Password="pass"
	s,err:=NewWithConfig(cfg);if err!=nil{t.Fatal(err)}
	ln,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
	go func(){_ = s.Serve(ln)}()
	t.Cleanup(func(){_ = ln.Close()})
	for _,v:=range []struct{user,pass string;result byte}{
		{"user","pass",0},
		{"user","bad",1},
	}{
		c,err:=net.Dial("tcp",ln.Addr().String());if err!=nil{t.Fatal(err)}
		_ = c.SetDeadline(time.Now().Add(3*time.Second))
		_,_ = c.Write([]byte{5,2,0,2})
		r:=make([]byte,2)
		_,err=io.ReadFull(c,r)
		if err!=nil || r[1]!=2 {t.Fatalf("expected password auth: %v %v",r,err)}
		auth:=append([]byte{1,byte(len(v.user))},[]byte(v.user)...)
		auth=append(auth,byte(len(v.pass)))
		auth=append(auth,[]byte(v.pass)...)
		_,_=c.Write(auth)
		_,err=io.ReadFull(c,r)
		_ = c.Close()
		if err!=nil || r[1]!=v.result {t.Errorf("auth result %v err %v",r,err)}
	}
}

func TestHTTPUpstreamConnect(t *testing.T) {
	ln,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
	defer ln.Close()
	go func(){
		c,err:=ln.Accept();if err!=nil{return}
		defer c.Close()
		b:=bufio.NewReader(c)
		line,_:=b.ReadString('\n')
		if !strings.Contains(line,"CONNECT echo.example:8443"){return}
		for {
			line,err=b.ReadString('\n');if err!=nil{return}
			if line=="\r\n"{break}
		}
		_,_=io.WriteString(c,"HTTP/1.1 200 Connection Established\r\n\r\n")
		_,_=io.Copy(c,c)
	}()
	ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
	c,err:=dialHTTP(ctx,Outbound{Type:"http",Address:ln.Addr().String()},"echo.example:8443")
	if err!=nil{t.Fatal(err)}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3*time.Second))
	_,_=c.Write([]byte("hello"))
	p:=make([]byte,5)
	_,err=io.ReadFull(c,p)
	if err!=nil || string(p)!="hello" {t.Fatalf("relay %q %v",p,err)}
}

func TestTrojanTLSVerifiedOutbound(t *testing.T) {
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
	now:=time.Now()
	template:=&x509.Certificate{
		SerialNumber:big.NewInt(42),NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),
		DNSNames:[]string{"localhost"},
		KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key)
	if err!=nil{t.Fatal(err)}
	cert:=tls.Certificate{Certificate:[][]byte{der},PrivateKey:key}
	ln,err:=tls.Listen("tcp","127.0.0.1:0",&tls.Config{Certificates:[]tls.Certificate{cert}})
	if err!=nil{t.Fatal(err)}
	defer ln.Close()
	go func(){
		c,err:=ln.Accept();if err!=nil{return}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3*time.Second))
		r:=bufio.NewReader(c)
		_,err=r.ReadString('\n')
		if err!=nil{return}
		dst:=make([]byte,1+1+1+len("example.com")+2+2)
		_,err=io.ReadFull(r,dst)
		if err!=nil || dst[0]!=1 {return}
		_,_=io.Copy(c,c)
	}()
	pemFile:=filepath.Join(t.TempDir(),"ca.pem")
	if err:=os.WriteFile(pemFile,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600);err!=nil{t.Fatal(err)}
	route:=Outbound{Type:"trojan",Address:ln.Addr().String(),Password:"secret",ServerName:"localhost",CAFile:pemFile}
	ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
	c,err:=dialTrojan(ctx,route,"example.com","443")
	if err!=nil {t.Fatal(err)}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3*time.Second))
	_,_=c.Write([]byte("ping"))
	b:=make([]byte,4)
	_,err=io.ReadFull(c,b)
	if err!=nil || string(b)!="ping" {t.Fatalf("trojan TLS relay %q %v",b,err)}
}
