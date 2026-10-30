package proxy

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil { return }
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func proxyServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	go func() { _ = New(3 * time.Second).Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func TestHTTPConnect(t *testing.T) {
	upstream := echoServer(t)
	proxy := proxyServer(t)
	c, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil { t.Fatal(err) }
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	_, _ = io.WriteString(c, "CONNECT "+upstream.Addr().String()+" HTTP/1.1\r\nHost: "+upstream.Addr().String()+"\r\n\r\n")
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") { t.Fatalf("response: %q %v", line, err) }
	_, _ = r.ReadString('\n')
	_, _ = c.Write([]byte("hello"))
	data := make([]byte, 5)
	_, err = io.ReadFull(r, data)
	if err != nil || string(data) != "hello" { t.Fatalf("relay %q %v", data, err) }
}

func TestHTTPRejectsGET(t *testing.T) {
	p := proxyServer(t)
	c, err := net.Dial("tcp", p.Addr().String())
	if err != nil { t.Fatal(err) }
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3*time.Second))
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.Contains(line, "405") { t.Fatalf("unexpected %q %v", line, err) }
}

func TestSOCKS5Connect(t *testing.T) {
	upstream := echoServer(t)
	proxy := proxyServer(t)
	c, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil { t.Fatal(err) }
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	_, err = io.ReadFull(c, greeting)
	if err != nil || greeting[0] != 5 || greeting[1] != 0 { t.Fatalf("greeting %v %v", greeting, err) }
	_, p, _ := net.SplitHostPort(upstream.Addr().String())
	port, _ := strconv.Atoi(p)
	portByte := make([]byte,2)
	binary.BigEndian.PutUint16(portByte,uint16(port))
	req := append([]byte{5, 1, 0, 1, 127, 0, 0, 1}, portByte...)
	_, _ = c.Write(req)
	reply := make([]byte, 10)
	_, err = io.ReadFull(c,reply)
	if err != nil || reply[1] != 0 { t.Fatalf("reply %v %v",reply,err) }
	_, _ = c.Write([]byte("pong"))
	buf := make([]byte,4)
	_, err = io.ReadFull(c,buf)
	if err != nil || string(buf) != "pong" { t.Fatalf("relay %q %v",buf,err) }
}

func TestSOCKS5RejectsNoAcceptableMethod(t *testing.T) {
	p := proxyServer(t)
	c, err := net.Dial("tcp", p.Addr().String())
	if err != nil { t.Fatal(err) }
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3*time.Second))
	_, _ = c.Write([]byte{5, 1, 2})
	reply := make([]byte, 2)
	_, err = io.ReadFull(c, reply)
	if err != nil || reply[1] != 0xff { t.Fatalf("reply %v %v", reply, err) }
}

func TestFutureProtocolsExplicitlyUnsupported(t *testing.T) {
	for _, proto := range []string{"shadowsocks-2022","hysteria2","vless-reality"} {
		if !strings.Contains(ProtocolStatus()[proto], "not yet supported") {
			t.Errorf("unsupported protocol %s misrepresented", proto)
		}
	}
}
