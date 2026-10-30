package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/jsw-teams/eproxy/internal/proxy"
)

func main() {
	path := flag.String("config", "", "read eproxy JSON config from a root-owned file")
	listen := flag.String("listen", "", "override config listener; loopback-only")
	checkConfig := flag.Bool("check-config", false, "validate config without opening a network listener")
	flag.Parse()

	cfg := proxy.DefaultConfig()
	if *path != "" {
		loaded, err := proxy.LoadConfig(*path)
		if err != nil {log.Fatalf("invalid configuration: %v",err)}
		cfg = loaded
	}
	if *listen!="" {cfg.Listen=*listen}
	s,err:=proxy.NewWithConfig(cfg)
	if err!=nil {log.Fatalf("configuration rejected: %v",err)}
	if *checkConfig {
		fmt.Println("eproxy configuration valid")
		return
	}
	if !isLoopbackAddr(cfg.Listen) {
		fmt.Fprintln(os.Stderr,"eproxy only listens on loopback interfaces")
		os.Exit(2)
	}
	ln,err:=net.Listen("tcp",cfg.Listen)
	if err!=nil {log.Fatal(err)}
	log.Printf("eproxy listening on %s (HTTP CONNECT and SOCKS5; configured routes)",ln.Addr())
	log.Fatal(s.Serve(ln))
}
func isLoopbackAddr(addr string) bool {
	host,_,err:=net.SplitHostPort(addr)
	if err!=nil {return false}
	if host=="localhost" {return true}
	ip:=net.ParseIP(host)
	return ip!=nil && ip.IsLoopback()
}
