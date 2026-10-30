package proxy

import (
    "encoding/binary"
    "io"
    "net"
    "testing"
    "time"
)

func TestSOCKS5UDPDNSStyleRelay(t *testing.T) {
    upstream,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1),Port:0})
    if err!=nil{t.Fatal(err)}
    defer upstream.Close()
    go func(){
        b:=make([]byte,2048)
        for {
            n,from,err:=upstream.ReadFromUDP(b)
            if err!=nil{return}
            _,_=upstream.WriteToUDP(b[:n],from)
        }
    }()
    cfg:=DefaultConfig()
    s,err:=NewWithConfig(cfg);if err!=nil{t.Fatal(err)}
    ln,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
    defer ln.Close()
    go func(){_ = s.Serve(ln)}()
    control,err:=net.Dial("tcp",ln.Addr().String())
    if err!=nil{t.Fatal(err)}
    defer control.Close()
    _ = control.SetDeadline(time.Now().Add(4*time.Second))
    _,_=control.Write([]byte{5,1,0})
    reply:=make([]byte,2)
    if _,err=io.ReadFull(control,reply);err!=nil || reply[1]!=0 {t.Fatalf("SOCKS method: %v %v",reply,err)}
    _,_=control.Write([]byte{5,3,0,1,0,0,0,0,0,0})
    udpReply:=make([]byte,10)
    if _,err=io.ReadFull(control,udpReply);err!=nil || udpReply[1]!=0 {t.Fatalf("UDP associate: %v %v",udpReply,err)}
    relayPort:=int(binary.BigEndian.Uint16(udpReply[8:]))
    conn,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1),Port:0})
    if err!=nil{t.Fatal(err)}
    defer conn.Close()
    target,err:=encodeTarget(upstream.LocalAddr().String())
    if err!=nil{t.Fatal(err)}
    packet:=append([]byte{0,0,0},target...)
    packet=append(packet,[]byte("udp-eproxy")...)
    relay:=&net.UDPAddr{IP:net.IPv4(127,0,0,1),Port:relayPort}
    _,err=conn.WriteToUDP(packet,relay)
    if err!=nil{t.Fatal(err)}
    _ = conn.SetReadDeadline(time.Now().Add(4*time.Second))
    b:=make([]byte,4096)
    n,_,err:=conn.ReadFromUDP(b)
    if err!=nil{t.Fatal(err)}
    _,_,response,err:=udpPacket(b[:n])
    if err!=nil || string(response)!="udp-eproxy" {t.Fatalf("UDP response %q %v",response,err)}
}

func TestUDPRejectsFragmentsAndMalformedHeaders(t *testing.T){
    invalid:=[][]byte{
        {0,0,1,1,127,0,0,1,0,80,3},
        {1,0,0,1,127,0,0,1,0,80,3},
        {0,0,0,5,127,0,0,1,0,80,3},
    }
    for _,p:=range invalid {
        if _,_,_,err:=udpPacket(p);err==nil {t.Fatalf("accepted malformed %v",p)}
    }
}
