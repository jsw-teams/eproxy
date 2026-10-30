// Package proxy implements a minimal, loopback-only, multiplexed HTTP CONNECT
// and SOCKS5 tunneling core. It does not implement encryption, TUN or DNS hijack.
package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

type Server struct {
	dialTimeout time.Duration
	config *Config
	resolver *NativeResolver
	slots chan struct{}
}

func New(timeout time.Duration) *Server {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Server{dialTimeout: timeout, slots: make(chan struct{}, 256)}
}

func NewWithConfig(cfg Config) (*Server,error) {
	if err:=cfg.Validate();err!=nil{return nil,err}
	s:=New(cfg.Deadline())
	s.config=&cfg
	if cfg.Engine=="native" {
		resolver,err:=NewNativeResolver(cfg)
		if err!=nil{return nil,err}
		s.resolver=resolver
	}
	return s,nil
}

func (s *Server) Serve(listener net.Listener) error {
	for {
		c, err := listener.Accept()
		if err != nil {
			return err
		}
		select {
		case s.slots <- struct{}{}:
			go func() { defer func(){<-s.slots}(); s.handle(c) }()
		default:
			_ = c.Close()
		}
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)
	prefix, err := reader.Peek(1)
	if err != nil {
		return
	}
	if prefix[0] == 0x05 {
		s.socks5(conn, reader)
	} else {
		s.httpConnect(conn, reader)
	}
}

func (s *Server) httpConnect(conn net.Conn, reader *bufio.Reader) {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	defer req.Body.Close()
	if req.Method != http.MethodConnect {
		s.forwardHTTP(conn, req)
		return
	}
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil || host == "" || port == "" {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if !s.httpAuthorized(req.Header.Get("Proxy-Authorization")) {
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"eproxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	dest, err := s.dialTarget(host, port)
	if err != nil {
		status := "502 Bad Gateway"
		if errors.Is(err,ErrBlocked) {status="403 Forbidden"}
		_, _ = io.WriteString(conn, "HTTP/1.1 "+status+"\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer dest.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	relay(conn, dest, reader)
}

func (s *Server) socks5(conn net.Conn, reader *bufio.Reader) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(reader, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}
	method := byte(0)
	if s.config!=nil && s.config.Username!="" { method=2 }
	found := false
	for _, offered := range methods {
		if offered == method { found = true }
	}
	if !found {
		_, _ = conn.Write([]byte{5, 0xff})
		return
	}
	if _, err := conn.Write([]byte{5, method}); err != nil { return }
	if method==2 && !s.socksAuthorized(conn,reader) { return }
	req := make([]byte, 4)
	if _, err := io.ReadFull(reader, req); err != nil || req[0] != 5 {
		return
	}
	if req[1] == 3 {
		s.udpAssociate(conn, reader, req[3])
		return
	}
	if req[1] != 1 {
		socksReply(conn, 7)
		return
	}
	var host string
	switch req[3] {
	case 1:
		data := make([]byte, 4)
		if _, err := io.ReadFull(reader, data); err != nil { return }
		host = net.IP(data).String()
	case 4:
		data := make([]byte, 16)
		if _, err := io.ReadFull(reader, data); err != nil { return }
		host = net.IP(data).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(reader, n[:]); err != nil || n[0] == 0 { return }
		data := make([]byte, int(n[0]))
		if _, err := io.ReadFull(reader, data); err != nil { return }
		host = string(data)
	default:
		socksReply(conn, 8)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBuf); err != nil { return }
	port := strconv.Itoa(int(binary.BigEndian.Uint16(portBuf)))
	dest, err := s.dialTarget(host, port)
	if err != nil {
		if errors.Is(err,ErrBlocked) {
			socksReply(conn,2)
		} else {
			socksReply(conn,5)
		}
		return
	}
	defer dest.Close()
	if err := socksReply(conn, 0); err != nil { return }
	_ = conn.SetReadDeadline(time.Time{})
	relay(conn, dest, reader)
}

func socksReply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func relay(client, server net.Conn, buffered *bufio.Reader) {
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(server, buffered)
		if tcp, ok := server.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(client, server)
	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	_ = server.SetDeadline(time.Now())
	<-done
}

var ErrNotReady = errors.New("protocol not yet supported")

// Future protocol implementations must provide their own authenticated,
// versioned handshake and interoperability tests before being enabled.
type Dialer interface {
	Protocol() string
	Dial(network, address string) (net.Conn, error)
}

func ProtocolStatus() map[string]string {
	return map[string]string{
		"http-connect": "implemented",
		"socks5-connect": "implemented",
		"shadowsocks-aead-aes-256-gcm": "implemented",
		"shadowsocks-2022": fmt.Sprint(ErrNotReady),
		"trojan": "implemented",
		"vless-tcp-tls": "implemented",
		"vless-reality": fmt.Sprint(ErrNotReady),
		"hysteria2": fmt.Sprint(ErrNotReady),
	}
}
