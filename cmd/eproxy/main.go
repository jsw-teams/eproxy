package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jsw-teams/eproxy/internal/proxy"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:1080", "loopback-only listener address")
	timeout := flag.Duration("dial-timeout", 10*time.Second, "upstream connection timeout")
	flag.Parse()
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || !isLoopback(host) {
		fmt.Fprintln(os.Stderr, "eproxy refuses non-loopback listeners (no authentication)")
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("eproxy listening on %s (HTTP CONNECT + SOCKS5)", ln.Addr())
	log.Fatal(proxy.New(*timeout).Serve(ln))
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
