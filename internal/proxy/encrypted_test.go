package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestShadowsocksAEADInteroperability(t *testing.T) {
	psk:=make([]byte,32)
	for i:=range psk {psk[i]=byte(i+1)}
	ln,err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil{t.Fatal(err)}
	defer ln.Close()
	serverErr:=make(chan error,1)
	go func(){
		c,err:=ln.Accept();if err!=nil {serverErr<-err;return}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4*time.Second))
		s:=&ssStream{Conn:c,psk:psk}
		target:=make([]byte,32)
		n,err:=s.Read(target)
		if err!=nil {serverErr<-err;return}
		expected,_:=encodeTarget("example.org:443")
		if string(target[:n])!=string(expected){serverErr<-io.ErrUnexpectedEOF;return}
		salt:=make([]byte,32)
		if _,err=rand.Read(salt);err!=nil{serverErr<-err;return}
		s.send,err=newSSAEAD(psk,salt)
		if err!=nil{serverErr<-err;return}
		if err=writeAll(c,salt);err!=nil{serverErr<-err;return}
		if _,err=s.Write([]byte("pong"));err!=nil{serverErr<-err;return}
		serverErr<-nil
	}()
	ctx,cancel:=context.WithTimeout(context.Background(),4*time.Second);defer cancel()
	c,err:=dialShadowsocks(ctx,Outbound{Type:"shadowsocks-aead",Address:ln.Addr().String(),Password:base64.StdEncoding.EncodeToString(psk)},"example.org:443")
	if err!=nil{t.Fatal(err)}
	_ = c.SetDeadline(time.Now().Add(4*time.Second))
	data:=make([]byte,4)
	_,err=io.ReadFull(c,data)
	_ = c.Close()
	if err!=nil || string(data)!="pong" {t.Fatalf("shadowsocks read %q %v",data,err)}
	if err=<-serverErr;err!=nil{t.Fatal(err)}
}

func TestVLESSVerifiedTLSInteroperability(t *testing.T) {
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
	now:=time.Now()
	template:=&x509.Certificate{
		SerialNumber:big.NewInt(44),NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),
		DNSNames:[]string{"localhost"},KeyUsage:x509.KeyUsageDigitalSignature,
		ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key)
	if err!=nil{t.Fatal(err)}
	cert:=tls.Certificate{Certificate:[][]byte{der},PrivateKey:key}
	ln,err:=tls.Listen("tcp","127.0.0.1:0",&tls.Config{Certificates:[]tls.Certificate{cert}})
	if err!=nil{t.Fatal(err)}
	defer ln.Close()
	serverErr:=make(chan error,1)
	go func(){
		c,err:=ln.Accept();if err!=nil{serverErr<-err;return}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4*time.Second))
		header:=make([]byte,1+16+1+1+2+1+1+11)
		if _,err=io.ReadFull(c,header);err!=nil{serverErr<-err;return}
		if header[0]!=0 || header[18]!=1 || header[21]!=2 {serverErr<-io.ErrUnexpectedEOF;return}
		p:=binary.BigEndian.Uint16(header[19:21])
		if p!=443 {serverErr<-io.ErrUnexpectedEOF;return}
		if err=writeAll(c,[]byte{0,0});err!=nil{serverErr<-err;return}
		_,err=c.Write([]byte("vless-ok"))
		serverErr<-err
	}()
	pemPath:=filepath.Join(t.TempDir(),"ca.pem")
	if err=os.WriteFile(pemPath,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600);err!=nil{t.Fatal(err)}
	route:=Outbound{Type:"vless",Address:ln.Addr().String(),UUID:"4e52614c-1e02-4527-9254-f6e8beeb53e8",ServerName:"localhost",CAFile:pemPath}
	ctx,cancel:=context.WithTimeout(context.Background(),4*time.Second);defer cancel()
	c,err:=dialVLESS(ctx,route,"example.org","443")
	if err!=nil{t.Fatal(err)}
	_ = c.SetDeadline(time.Now().Add(4*time.Second))
	data:=make([]byte,len("vless-ok"))
	_,err=io.ReadFull(c,data)
	_ = c.Close()
	if err!=nil || string(data)!="vless-ok" {t.Fatalf("vless read %q %v",data,err)}
	if err=<-serverErr;err!=nil{t.Fatal(err)}
}
