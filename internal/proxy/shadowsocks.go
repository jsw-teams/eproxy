package proxy

// Implements Shadowsocks TCP AEAD (SIP004) using AES-256-GCM.
// This is the pre-2022 AEAD specification; SS-2022 is NOT claimed.
import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const ssChunkLimit=0x3fff
const ssTagLen=16

type ssStream struct {
	net.Conn
	psk []byte
	send cipher.AEAD
	receive cipher.AEAD
	sendNonce [12]byte
	readNonce [12]byte
	readBuf []byte
	writeLock sync.Mutex
	readLock sync.Mutex
}

func hkdfSHA1(key,salt []byte,size int) []byte {
	extract:=hmac.New(sha1.New,salt)
	extract.Write(key)
	prk:=extract.Sum(nil)
	var result,prev []byte
	for i:=byte(1);len(result)<size;i++ {
		mac:=hmac.New(sha1.New,prk)
		mac.Write(prev)
		mac.Write([]byte("ss-subkey"))
		mac.Write([]byte{i})
		prev=mac.Sum(nil)
		result=append(result,prev...)
	}
	return result[:size]
}
func newSSAEAD(psk,salt []byte)(cipher.AEAD,error) {
	subkey:=hkdfSHA1(psk,salt,32)
	block,err:=aes.NewCipher(subkey)
	if err!=nil{return nil,err}
	return cipher.NewGCM(block)
}
func stepNonce(n *[12]byte) {
	for i:=range n {
		n[i]++
		if n[i]!=0 {break}
	}
}
func dialShadowsocks(ctx context.Context,route Outbound,target string)(net.Conn,error) {
	psk,err:=base64.StdEncoding.DecodeString(route.Password)
	if err!=nil || len(psk)!=32 {return nil,errors.New("Shadowsocks AES-256-GCM requires a 32-byte base64 key")}
	c,err:=dialUpstream(ctx,route.Address)
	if err!=nil{return nil,err}
	ok:=false
	defer func(){if !ok {_=c.Close()}}()
	_ = c.SetDeadline(time.Now().Add(10*time.Second))
	salt:=make([]byte,32)
	if _,err=rand.Read(salt);err!=nil{return nil,err}
	send,err:=newSSAEAD(psk,salt)
	if err!=nil{return nil,err}
	if _,err=c.Write(salt);err!=nil{return nil,err}
	stream:=&ssStream{Conn:c,psk:psk,send:send}
	dst,err:=encodeTarget(target)
	if err!=nil{return nil,err}
	if _,err=stream.Write(dst);err!=nil{return nil,err}
	_ = c.SetDeadline(time.Time{})
	ok=true
	return stream,nil
}
func (s *ssStream) Write(p []byte)(int,error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()
	total:=0
	for len(p)>0 {
		n:=len(p)
		if n>ssChunkLimit {n=ssChunkLimit}
		var length [2]byte
		binary.BigEndian.PutUint16(length[:],uint16(n))
		frame:=s.send.Seal(nil,s.sendNonce[:],length[:],nil)
		stepNonce(&s.sendNonce)
		frame=append(frame,s.send.Seal(nil,s.sendNonce[:],p[:n],nil)...)
		stepNonce(&s.sendNonce)
		if err:=writeAll(s.Conn,frame);err!=nil{return total,err}
		total+=n
		p=p[n:]
	}
	return total,nil
}
func writeAll(w io.Writer,p []byte)error {
	for len(p)>0 {
		n,err:=w.Write(p)
		if err!=nil{return err}
		if n==0{return io.ErrShortWrite}
		p=p[n:]
	}
	return nil
}
func (s *ssStream) Read(p []byte)(int,error) {
	if len(p)==0{return 0,nil}
	s.readLock.Lock()
	defer s.readLock.Unlock()
	if len(s.readBuf)==0 {
		if s.receive==nil {
			salt:=make([]byte,32)
			if _,err:=io.ReadFull(s.Conn,salt);err!=nil{return 0,err}
			var err error
			s.receive,err=newSSAEAD(s.psk,salt)
			if err!=nil{return 0,err}
		}
		lengthCipher:=make([]byte,2+ssTagLen)
		if _,err:=io.ReadFull(s.Conn,lengthCipher);err!=nil{return 0,err}
		length,err:=s.receive.Open(nil,s.readNonce[:],lengthCipher,nil)
		if err!=nil{return 0,err}
		stepNonce(&s.readNonce)
		n:=int(binary.BigEndian.Uint16(length))
		if n==0 || n>ssChunkLimit{return 0,errors.New("invalid Shadowsocks frame length")}
		payloadCipher:=make([]byte,n+ssTagLen)
		if _,err:=io.ReadFull(s.Conn,payloadCipher);err!=nil{return 0,err}
		s.readBuf,err=s.receive.Open(nil,s.readNonce[:],payloadCipher,nil)
		if err!=nil{return 0,err}
		stepNonce(&s.readNonce)
	}
	n:=copy(p,s.readBuf)
	s.readBuf=s.readBuf[n:]
	return n,nil
}
