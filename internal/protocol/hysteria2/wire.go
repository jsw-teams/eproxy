// Package hysteria2 contains an original encoder/decoder for the public
// Hysteria 2 QUIC stream/datagram wire format.
//
// It DOES NOT provide a QUIC transport, HTTP/3 /auth handshake, authentication,
// congestion control, obfuscation, fragmentation reassembly, or a working proxy.
// The package is intentionally separate so these requirements are never
// confused with a functioning Hysteria2 outbound.
package hysteria2

import (
    "bufio"
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "net"
    "strconv"
    "strings"
)

const (
    tcpRequestID = 0x401
    maxVarInt = (uint64(1)<<62)-1
    maxAddress = 1024
    maxMessage = 4096
    maxPadding = 4096
    maxDatagram = 65535
)
func writeVarInt(w io.Writer, v uint64) error {
    if v>maxVarInt{return errors.New("QUIC varint exceeds 62 bits")}
    var out [8]byte
    n:=1
    switch {
    case v<1<<6: out[0]=byte(v)
    case v<1<<14: n=2;binary.BigEndian.PutUint16(out[:2],uint16(v)|0x4000)
    case v<1<<30: n=4;binary.BigEndian.PutUint32(out[:4],uint32(v)|0x80000000)
    default: n=8;binary.BigEndian.PutUint64(out[:8],v|0xc000000000000000)
    }
    _,err:=w.Write(out[:n])
    return err
}
func readVarInt(r io.ByteReader)(uint64,error) {
    first,err:=r.ReadByte()
    if err!=nil{return 0,err}
    n:=1<<uint(first>>6)
    v:=uint64(first&0x3f)
    for i:=1;i<n;i++{
        b,err:=r.ReadByte()
        if err!=nil{return 0,err}
        v=v<<8|uint64(b)
    }
    return v,nil
}
func validAddress(addr string)bool {
    host,port,err:=net.SplitHostPort(addr)
    if err!=nil || host=="" || port=="" || len(addr)>maxAddress ||
        strings.ContainsAny(host,"\x00\r\n /") {return false}
    n,e:=strconv.Atoi(port)
    return e==nil && n>0 && n<=65535
}
func WriteTCPRequest(w io.Writer,addr string,padding []byte)error {
    if !validAddress(addr) {return errors.New("invalid Hysteria2 TCP target")}
    if len(padding)>maxPadding {return errors.New("padding exceeds limit")}
    if err:=writeVarInt(w,tcpRequestID);err!=nil{return err}
    if err:=writeVarInt(w,uint64(len(addr)));err!=nil{return err}
    if _,err:=io.WriteString(w,addr);err!=nil{return err}
    if err:=writeVarInt(w,uint64(len(padding)));err!=nil{return err}
    _,err:=w.Write(padding)
    return err
}
type TCPResponse struct {
    Status byte
    Message string
}
// The caller must reuse the same buffered reader for subsequent stream data.
func ReadTCPResponse(r *bufio.Reader)(TCPResponse,error) {
    var header [1]byte
    if _,err:=io.ReadFull(r,header[:]);err!=nil{return TCPResponse{},err}
    if header[0]!=0 && header[0]!=1 {return TCPResponse{},errors.New("invalid Hysteria2 TCP status")}
    msgSize,err:=readVarInt(r)
    if err!=nil{return TCPResponse{},err}
    if msgSize>maxMessage{return TCPResponse{},errors.New("message too long")}
    msg:=make([]byte,int(msgSize))
    if _,err:=io.ReadFull(r,msg);err!=nil{return TCPResponse{},err}
    paddingSize,err:=readVarInt(r)
    if err!=nil{return TCPResponse{},err}
    if paddingSize>maxPadding{return TCPResponse{},errors.New("padding too long")}
    if _,err:=io.CopyN(io.Discard,r,int64(paddingSize));err!=nil{return TCPResponse{},err}
    return TCPResponse{Status:header[0],Message:string(msg)},nil
}
// UDPDatagram is one Hysteria2 QUIC DATAGRAM with a complete, unfragmented
// packet. Fragmented data are explicitly rejected until a bounded reassembler
// with timeouts and memory limits is implemented.
type UDPDatagram struct {
    SessionID uint32
    PacketID uint16
    Address string
    Payload []byte
}
func EncodeUDP(d UDPDatagram)([]byte,error) {
    if !validAddress(d.Address){return nil,errors.New("invalid UDP address")}
    if len(d.Payload)>maxDatagram{return nil,errors.New("UDP data too large")}
    var buf bytes.Buffer
    var hdr [8]byte
    binary.BigEndian.PutUint32(hdr[0:4],d.SessionID)
    binary.BigEndian.PutUint16(hdr[4:6],d.PacketID)
    hdr[6]=0
    hdr[7]=1 // Fragment ID zero, count one.
    _,_ = buf.Write(hdr[:])
    if err:=writeVarInt(&buf,uint64(len(d.Address)));err!=nil{return nil,err}
    _,_ = buf.WriteString(d.Address)
    _,_ = buf.Write(d.Payload)
    if buf.Len()>maxDatagram {return nil,errors.New("UDP datagram exceeds limit")}
    return buf.Bytes(),nil
}
func DecodeUDP(raw []byte)(UDPDatagram,error){
    if len(raw)<9 || len(raw)>maxDatagram{return UDPDatagram{},errors.New("invalid datagram size")}
    id:=binary.BigEndian.Uint32(raw[:4])
    pid:=binary.BigEndian.Uint16(raw[4:6])
    if raw[6]!=0 || raw[7]!=1 {return UDPDatagram{},errors.New("fragmented UDP not yet supported")}
    r:=bytes.NewReader(raw[8:])
    size,err:=readVarInt(r)
    if err!=nil{return UDPDatagram{},err}
    if size==0 || size>maxAddress || size>uint64(r.Len()) {return UDPDatagram{},errors.New("invalid datagram address length")}
    b:=make([]byte,int(size))
    if _,err:=io.ReadFull(r,b);err!=nil{return UDPDatagram{},err}
    if !validAddress(string(b)){return UDPDatagram{},fmt.Errorf("invalid datagram target %q",string(b))}
    rest,err:=io.ReadAll(r)
    if err!=nil{return UDPDatagram{},err}
    return UDPDatagram{SessionID:id,PacketID:pid,Address:string(b),Payload:rest},nil
}
