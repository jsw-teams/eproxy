package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}
func (c *bufferedConn) Read(p []byte)(int,error) {return c.reader.Read(p)}

func (s *Server) dialTarget(host, port string) (net.Conn,error) {
	target:=net.JoinHostPort(host,port)
	if s.config==nil {
		return net.DialTimeout("tcp",target,s.dialTimeout)
	}
	route,blocked:=s.config.OutboundFor(host)
	if blocked {return nil,ErrBlocked}
	timeout:=s.config.Deadline()
	ctx,cancel:=context.WithTimeout(context.Background(),timeout)
	defer cancel()
	switch route.Type {
	case "direct":
		return s.dialDirect(ctx,host,port)
	case "http":
		return dialHTTP(ctx,route,target)
	case "socks5":
		return dialSocks(ctx,route,target)
	case "trojan":
		return dialTrojan(ctx,route,host,port)
	case "vless":
		return dialVLESS(ctx,route,host,port)
	case "shadowsocks-aead":
		return dialShadowsocks(ctx,route,target)
	default:
		return nil,fmt.Errorf("invalid outbound type %q",route.Type)
	}
}

func dialHTTP(ctx context.Context,route Outbound,target string)(net.Conn,error) {
	c,err:=(&net.Dialer{}).DialContext(ctx,"tcp",route.Address)
	if err!=nil{return nil,err}
	ok:=false
	defer func(){if !ok {_=c.Close()}}()
	_ = c.SetDeadline(time.Now().Add(10*time.Second))
	auth:=""
	if route.Username!="" {
		auth="Proxy-Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte(route.Username+":"+route.Password))+"\r\n"
	}
	_,err=io.WriteString(c,"CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n"+auth+"\r\n")
	if err!=nil{return nil,err}
	b:=bufio.NewReader(c)
	resp,err:=http.ReadResponse(b,&http.Request{Method:http.MethodConnect})
	if err!=nil{return nil,err}
	if resp.StatusCode!=200 {
		_ = resp.Body.Close()
		return nil,fmt.Errorf("upstream HTTP CONNECT rejected: %d",resp.StatusCode)
	}
	_ = c.SetDeadline(time.Time{})
	ok=true
	return &bufferedConn{Conn:c,reader:b},nil
}

func dialSocks(ctx context.Context,route Outbound,target string)(net.Conn,error) {
	c,err:=(&net.Dialer{}).DialContext(ctx,"tcp",route.Address)
	if err!=nil{return nil,err}
	ok:=false
	defer func(){if !ok {_=c.Close()}}()
	_ = c.SetDeadline(time.Now().Add(10*time.Second))
	method:=byte(0)
	if route.Username!="" {method=2}
	if _,err=c.Write([]byte{5,1,method});err!=nil{return nil,err}
	reply:=make([]byte,2)
	if _,err=io.ReadFull(c,reply);err!=nil{return nil,err}
	if reply[0]!=5 || reply[1]!=method {return nil,errors.New("upstream SOCKS5 authentication method rejected")}
	if method==2 {
		if len(route.Username)>255 || len(route.Password)>255 {return nil,errors.New("SOCKS5 credentials too long")}
		b:=append([]byte{1,byte(len(route.Username))},[]byte(route.Username)...)
		b=append(b,byte(len(route.Password)))
		b=append(b,[]byte(route.Password)...)
		if _,err=c.Write(b);err!=nil{return nil,err}
		if _,err=io.ReadFull(c,reply);err!=nil{return nil,err}
		if reply[0]!=1 || reply[1]!=0 {return nil,errors.New("upstream SOCKS5 login rejected")}
	}
	addr,err:=encodeTarget(target)
	if err!=nil{return nil,err}
	pkt:=append([]byte{5,1,0},addr...)
	if _,err=c.Write(pkt);err!=nil{return nil,err}
	hdr:=make([]byte,4)
	if _,err=io.ReadFull(c,hdr);err!=nil{return nil,err}
	if hdr[0]!=5 || hdr[1]!=0 {return nil,fmt.Errorf("upstream SOCKS5 connection rejected: %d",hdr[1])}
	switch hdr[3] {
	case 1: _,err=io.CopyN(io.Discard,c,6)
	case 4: _,err=io.CopyN(io.Discard,c,18)
	case 3:
		n:=make([]byte,1)
		if _,err=io.ReadFull(c,n);err==nil {_,err=io.CopyN(io.Discard,c,int64(n[0])+2)}
	default: err=errors.New("invalid upstream SOCKS5 reply address")
	}
	if err!=nil{return nil,err}
	_ = c.SetDeadline(time.Time{})
	ok=true
	return c,nil
}

// Trojan outbound: TLS with server certificate verification, SHA224(password)
// followed by TCP CONNECT request. TLS encryption is provided by Go crypto/tls.
func dialTrojan(ctx context.Context,route Outbound,host,port string)(net.Conn,error) {
	tlsCfg:=&tls.Config{ServerName:route.ServerName,MinVersion:tls.VersionTLS12}
	if route.CAFile!="" {
		pem,err:=os.ReadFile(route.CAFile)
		if err!=nil{return nil,err}
		pool,err:=x509.SystemCertPool()
		if err!=nil || pool==nil {pool=x509.NewCertPool()}
		if !pool.AppendCertsFromPEM(pem) {return nil,errors.New("invalid Trojan CA certificate")}
		tlsCfg.RootCAs=pool
	}
	raw,err:=(&net.Dialer{}).DialContext(ctx,"tcp",route.Address)
	if err!=nil{return nil,err}
	c:=tls.Client(raw,tlsCfg)
	ok:=false
	defer func(){if !ok {_=c.Close()}}()
	_ = c.SetDeadline(time.Now().Add(10*time.Second))
	if err=c.HandshakeContext(ctx);err!=nil{return nil,err}
	dst,err:=encodeTarget(net.JoinHostPort(host,port))
	if err!=nil{return nil,err}
	sha:=sha256.Sum224([]byte(route.Password))
	req:=append([]byte(hex.EncodeToString(sha[:])+"\r\n"),1)
	req=append(req,dst...)
	req=append(req,'\r','\n')
	if _,err=c.Write(req);err!=nil{return nil,err}
	_ = c.SetDeadline(time.Time{})
	ok=true
	return c,nil
}

func encodeTarget(target string)([]byte,error) {
	host,port,err:=net.SplitHostPort(target)
	if err!=nil{return nil,err}
	n,err:=strconv.Atoi(port)
	if err!=nil || n<1 || n>65535 {return nil,errors.New("invalid target port")}
	var payload []byte
	ip:=net.ParseIP(host)
	switch {
	case ip!=nil && ip.To4()!=nil:
		payload=append([]byte{1},ip.To4()...)
	case ip!=nil && ip.To16()!=nil:
		payload=append([]byte{4},ip.To16()...)
	case len(host)>0 && len(host)<256 && !strings.ContainsAny(host,"\r\n\x00"):
		payload=append([]byte{3,byte(len(host))},[]byte(host)...)
	default:return nil,errors.New("invalid target hostname")
	}
	out:=make([]byte,2)
	binary.BigEndian.PutUint16(out,uint16(n))
	return append(payload,out...),nil
}


// dialDirect resolves with eproxy's own verified DoH transport. A DNS
// failure never falls back to the OS resolver or cleartext port 53.
func (s *Server) dialDirect(ctx context.Context,host,port string)(net.Conn,error){
	if s.resolver==nil {
		return (&net.Dialer{Timeout:s.dialTimeout}).DialContext(ctx,"tcp",net.JoinHostPort(host,port))
	}
	ips,err:=s.resolver.LookupIP(ctx,host)
	if err!=nil {return nil,err}
	dialer:=&net.Dialer{Timeout:s.dialTimeout}
	var last error
	for _,ip:=range ips {
		c,err:=dialer.DialContext(ctx,"tcp",net.JoinHostPort(ip.String(),port))
		if err==nil{return c,nil}
		last=err
	}
	return nil,last
}
