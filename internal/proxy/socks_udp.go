package proxy

// SOCKS5 UDP ASSOCIATE (RFC 1928), direct outbound only.
// Deliberately bound to 127.0.0.1, with each association tied to its
// authenticated TCP control connection and a single UDP source.
import (
    "context"
    "encoding/binary"
    "errors"
    "io"
    "net"
    "strconv"
    "sync"
    "time"
)

func udpPacket(b []byte)(host,port string,payload []byte,err error) {
    if len(b)<7 || b[0]!=0 || b[1]!=0 || b[2]!=0 {
        return "","",nil,errors.New("invalid SOCKS5 UDP header or fragmented packet")
    }
    pos:=4
    switch b[3] {
    case 1:
        if len(b)<pos+4+2 {return "","",nil,io.ErrUnexpectedEOF}
        host=net.IP(b[pos:pos+4]).String();pos+=4
    case 4:
        if len(b)<pos+16+2 {return "","",nil,io.ErrUnexpectedEOF}
        host=net.IP(b[pos:pos+16]).String();pos+=16
    case 3:
        if len(b)<pos+1 {return "","",nil,io.ErrUnexpectedEOF}
        n:=int(b[pos]);pos++
        if n==0 || len(b)<pos+n+2 {return "","",nil,io.ErrUnexpectedEOF}
        host=string(b[pos:pos+n]);pos+=n
    default:
        return "","",nil,errors.New("unknown UDP address type")
    }
    n:=int(binary.BigEndian.Uint16(b[pos:pos+2]))
    if n<1 {return "","",nil,errors.New("invalid UDP destination port")}
    return host,strconv.Itoa(n),b[pos+2:],nil
}

// Consume the source client request address before opening the relay.
func consumeSocksAddress(r io.Reader,atype byte)(int,error) {
    var n int
    switch atype {
    case 1:n=4
    case 4:n=16
    case 3:
        var sz [1]byte
        if _,err:=io.ReadFull(r,sz[:]);err!=nil{return 0,err}
        n=int(sz[0]);if n==0{return 0,errors.New("empty UDP host")}
    default:return 0,errors.New("unsupported UDP request address type")
    }
    buf:=make([]byte,n+2)
    if _,err:=io.ReadFull(r,buf);err!=nil{return 0,err}
    return int(binary.BigEndian.Uint16(buf[len(buf)-2:])),nil
}

func (s *Server) udpAssociate(control net.Conn,reader io.Reader,atype byte) {
    requestedPort,err:=consumeSocksAddress(reader,atype)
    if err!=nil {_,_ = control.Write([]byte{5,8,0,1,0,0,0,0,0,0});return}
    local,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1),Port:0})
    if err!=nil {_,_ = control.Write([]byte{5,1,0,1,0,0,0,0,0,0});return}
    defer local.Close()
    port:=local.LocalAddr().(*net.UDPAddr).Port
    reply:=[]byte{5,0,0,1,127,0,0,1,byte(port>>8),byte(port)}
    if _,err=control.Write(reply);err!=nil{return}
    peer:=control.RemoteAddr().(*net.TCPAddr).IP
    done:=make(chan struct{})
    var wg sync.WaitGroup
    workers:=make(chan struct{},16)
    go func(){
        defer close(done)
        var sourcePort int
        packet:=make([]byte,65535)
        for {
            n,from,err:=local.ReadFromUDP(packet)
            if err!=nil{return}
            if !from.IP.Equal(peer) {continue}
            if requestedPort!=0 && from.Port!=requestedPort {continue}
            if sourcePort==0 {sourcePort=from.Port}
            if from.Port!=sourcePort {continue}
            host,dport,payload,err:=udpPacket(packet[:n])
            if err!=nil{continue}
            ob:=Outbound{Type:"direct"}
            blocked:=false
            if s.config!=nil {ob,blocked=s.config.OutboundFor(host)}
            if blocked || ob.Type!="direct" {continue}
            addr:=net.JoinHostPort(host,dport)
            // Resolve UDP targets through the same native DoH policy.
            if s.resolver!=nil {
                ctx,cancel:=context.WithTimeout(context.Background(),s.dialTimeout)
                ips,resolveErr:=s.resolver.LookupIP(ctx,host)
                cancel()
                if resolveErr!=nil || len(ips)==0 {continue}
                addr=net.JoinHostPort(ips[0].String(),dport)
            }
            target,err:=net.ResolveUDPAddr("udp",addr)
            if err!=nil {continue}
            select {
            case workers<-struct{}{}:
            default:continue
            }
            copyPayload:=append([]byte(nil),payload...)
            originalFrom:=*from
            wg.Add(1)
            go func() {
                defer wg.Done()
                defer func(){<-workers}()
                remote,err:=net.DialUDP("udp",nil,target)
                if err!=nil{return}
                defer remote.Close()
                _ = remote.SetDeadline(time.Now().Add(3*time.Second))
                if _,err=remote.Write(copyPayload);err!=nil{return}
                buf:=make([]byte,65535)
                n,err:=remote.Read(buf)
                if err!=nil{return}
                header,err:=encodeTarget(target.String())
                if err!=nil{return}
                response:=append([]byte{0,0,0},header...)
                response=append(response,buf[:n]...)
                _,_=local.WriteToUDP(response,&originalFrom)
            }()
        }
    }()
    _,_ = io.Copy(io.Discard,control)
    _ = local.Close()
    <-done
    wg.Wait()
}
