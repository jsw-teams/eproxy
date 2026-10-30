package hysteria2

import (
    "bufio"
    "bytes"
    "encoding/hex"
    "io"
    "net"
    "testing"
)

func TestQUICVarIntBoundaries(t *testing.T){
    cases:=[]struct{number uint64; size int}{
        {0,1},{63,1},{64,2},{16383,2},{16384,4},
        {(1<<30)-1,4},{1<<30,8},{maxVarInt,8},
    }
    for _,c:=range cases {
        var b bytes.Buffer
        if err:=writeVarInt(&b,c.number);err!=nil{t.Fatal(err)}
        if b.Len()!=c.size {t.Errorf("value %d expected %d bytes got %d",c.number,c.size,b.Len())}
        decoded,err:=readVarInt(bufio.NewReader(&b))
        if err!=nil || decoded!=c.number{t.Errorf("%d: decoded %d err %v",c.number,decoded,err)}
    }
    if err:=writeVarInt(io.Discard,maxVarInt+1);err==nil{t.Fatal("accepted QUIC varint overflow")}
}

func TestHysteriaTCPRequestPublicSpec(t *testing.T) {
    var b bytes.Buffer
    if err:=WriteTCPRequest(&b,"example.org:443",[]byte{0x01,0x02});err!=nil{t.Fatal(err)}
    data:=b.Bytes()
    if len(data)<5 || data[0]!=0x44 || data[1]!=0x01 {t.Fatalf("wrong TCP request ID encoding: %s",hex.EncodeToString(data))}
    r:=bufio.NewReader(&b)
    id,err:=readVarInt(r)
    if err!=nil || id!=tcpRequestID {t.Fatalf("wrong TCP request ID %d %v",id,err)}
    length,err:=readVarInt(r)
    if err!=nil || length!=15 {t.Fatalf("address length %d %v",length,err)}
    raw:=make([]byte,length)
    if _,err:=io.ReadFull(r,raw);err!=nil || string(raw)!="example.org:443" {t.Fatalf("target %q %v",raw,err)}
    n,err:=readVarInt(r)
    if err!=nil || n!=2{t.Fatalf("padding length %d %v",n,err)}
    pad:=make([]byte,2)
    if _,err:=io.ReadFull(r,pad);err!=nil || !bytes.Equal(pad,[]byte{1,2}) {t.Fatalf("padding %v %v",pad,err)}
}

func TestHysteriaTCPResponseLeavesStreamData(t *testing.T) {
    // Status 0, response message size 0, padding size 0, then user payload.
    reader:=bufio.NewReader(bytes.NewReader([]byte{0,0,0,'h','e','l','l','o'}))
    resp,err:=ReadTCPResponse(reader)
    if err!=nil || resp.Status!=0 {t.Fatalf("response %+v %v",resp,err)}
    payload,err:=io.ReadAll(reader)
    if err!=nil || string(payload)!="hello" {t.Fatalf("lost TCP stream payload %q %v",payload,err)}
}
func TestUDPDatagramRoundTripAndFragmentReject(t *testing.T){
    original:=UDPDatagram{SessionID:0xfefefefe,PacketID:42,Address:net.JoinHostPort("example.org","443"),Payload:[]byte("packet payload")}
    raw,err:=EncodeUDP(original)
    if err!=nil{t.Fatal(err)}
    decoded,err:=DecodeUDP(raw)
    if err!=nil || decoded.Address!=original.Address || decoded.SessionID!=original.SessionID ||
        decoded.PacketID!=original.PacketID || !bytes.Equal(decoded.Payload,original.Payload) {
        t.Fatalf("UDP mismatch %+v %v",decoded,err)
    }
    raw[7]=2
    if _,err:=DecodeUDP(raw);err==nil{t.Fatal("fragmented packet was silently accepted")}
}
func TestMalformedFrames(t *testing.T){
    if err:=WriteTCPRequest(io.Discard,"not-a-host",nil);err==nil{t.Fatal("invalid target accepted")}
    for _,payload:=range [][]byte{
        {},{1,0,0},{2,0,0},{0,0},{0,0,0xff},
    } {
        _,err:=ReadTCPResponse(bufio.NewReader(bytes.NewReader(payload)))
        if len(payload)>0 && payload[0]==1 && len(payload)==3 { // explicit remote error response is valid
            if err!=nil{t.Fatal(err)}
        }else if err==nil {t.Errorf("unexpected success for %v",payload)}
    }
    _,err:=DecodeUDP([]byte{0,0,0,1,0,0,0,1,0})
    if err==nil{t.Fatal("zero-length UDP address accepted")}
}
