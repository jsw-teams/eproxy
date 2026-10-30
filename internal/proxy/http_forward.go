package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var ErrBlocked=errors.New("blocked by eproxy routing rule")

// forwardHTTP supports a single absolute-form HTTP proxy request.
// It never forwards proxy credentials to the destination.
func (s *Server) forwardHTTP(client net.Conn,req *http.Request) {
	if !s.httpAuthorized(req.Header.Get("Proxy-Authorization")) {
		_,_=io.WriteString(client,"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"eproxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	if req.URL==nil || req.URL.Scheme!="http" || !req.URL.IsAbs() || req.URL.Host=="" || req.URL.User!=nil {
		_,_=io.WriteString(client,"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return
	}
	hostname:=req.URL.Hostname()
	port:=req.URL.Port()
	if port=="" {port="80"}
	if hostname=="" || strings.ContainsAny(hostname,"\r\n") {
		_,_=io.WriteString(client,"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return
	}
	dest,err:=s.dialTarget(hostname,port)
	if err!=nil {
		code:="502 Bad Gateway"
		if errors.Is(err,ErrBlocked) {code="403 Forbidden"}
		_,_=io.WriteString(client,"HTTP/1.1 "+code+"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer dest.Close()
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Connection")
	req.Header.Del("Keep-Alive")
	req.URL.Scheme=""
	req.URL.Host=""
	req.RequestURI=""
	req.Close=true
	req.Header.Set("Connection","close")
	_ = client.SetReadDeadline(time.Time{})
	if err=req.Write(dest);err!=nil{return}
	_,_=io.Copy(client,bufio.NewReader(dest))
}
