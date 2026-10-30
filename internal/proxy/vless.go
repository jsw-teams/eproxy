package proxy

// VLESS TCP over verified TLS. REALITY, XTLS, WS, gRPC and UDP are not
// implemented. The VLESS transport itself does not provide encryption.
import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func parseUUID(value string)([16]byte,error) {
	var result [16]byte
	raw:=strings.ReplaceAll(value,"-","")
	if len(raw)!=32 {return result,errors.New("invalid VLESS UUID")}
	data,err:=hex.DecodeString(raw)
	if err!=nil{return result,err}
	copy(result[:],data)
	return result,nil
}
func tlsClient(ctx context.Context,route Outbound)(*tls.Conn,error) {
	cfg:=&tls.Config{ServerName:route.ServerName,MinVersion:tls.VersionTLS12}
	if route.CAFile!="" {
		pem,err:=os.ReadFile(route.CAFile)
		if err!=nil{return nil,err}
		pool,err:=x509.SystemCertPool()
		if err!=nil || pool==nil {pool=x509.NewCertPool()}
		if !pool.AppendCertsFromPEM(pem){return nil,errors.New("invalid CA PEM")}
		cfg.RootCAs=pool
	}
	raw,err:=dialUpstream(ctx,route.Address)
	if err!=nil{return nil,err}
	conn:=tls.Client(raw,cfg)
	_ = conn.SetDeadline(time.Now().Add(10*time.Second))
	if err=conn.HandshakeContext(ctx);err!=nil {_=conn.Close();return nil,err}
	return conn,nil
}
func dialVLESS(ctx context.Context,route Outbound,host,port string)(net.Conn,error) {
	uid,err:=parseUUID(route.UUID)
	if err!=nil{return nil,err}
	c,err:=tlsClient(ctx,route)
	if err!=nil{return nil,err}
	ok:=false
	defer func(){if !ok {_=c.Close()}}()
	pn,err:=strconv.Atoi(port)
	if err!=nil || pn<1 || pn>65535{return nil,errors.New("invalid VLESS target port")}
	payload:=make([]byte,0,64)
	payload=append(payload,0)
	payload=append(payload,uid[:]...)
	payload=append(payload,0,1) // addons len=0, command TCP=1
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:],uint16(pn))
	payload=append(payload,portBytes[:]...)
	ip:=net.ParseIP(host)
	switch {
	case ip!=nil && ip.To4()!=nil:
		payload=append(payload,1)
		payload=append(payload,ip.To4()...)
	case ip!=nil:
		payload=append(payload,3)
		payload=append(payload,ip.To16()...)
	case len(host)>0 && len(host)<=255 && !strings.ContainsAny(host,"\x00\r\n"):
		payload=append(payload,2,byte(len(host)))
		payload=append(payload,[]byte(host)...)
	default:return nil,errors.New("invalid VLESS target host")
	}
	if err:=writeAll(c,payload);err!=nil{return nil,err}
	_ = c.SetDeadline(time.Time{})
	ok=true
	return &vlessStream{Conn:c},nil
}
type vlessStream struct {
	net.Conn
	once sync.Once
	responseErr error
}
func (s *vlessStream) Read(p []byte)(int,error) {
	s.once.Do(func(){
		buf:=make([]byte,2)
		if _,err:=io.ReadFull(s.Conn,buf);err!=nil{s.responseErr=err;return}
		if buf[0]!=0 {s.responseErr=errors.New("unexpected VLESS response version");return}
		if buf[1]>0 {_,s.responseErr=io.CopyN(io.Discard,s.Conn,int64(buf[1]))}
	})
	if s.responseErr!=nil{return 0,s.responseErr}
	return s.Conn.Read(p)
}
