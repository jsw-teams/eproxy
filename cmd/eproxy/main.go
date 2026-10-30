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
	uci := flag.String("uci", "", "read OpenWrt UCI config directly; mutually exclusive with -config")
	listen := flag.String("listen", "", "override config listener; loopback-only")
	checkConfig := flag.Bool("check-config", false, "validate config without opening a network listener")
	export := flag.String("export-singbox", "", "generate private sing-box configuration and exit")
    providerCache:=flag.String("provider-cache", "", "private cached subscription nodes JSON")
    syncSubscriptions:=flag.String("sync-subscriptions", "", "download HTTPS subscriptions into a private provider cache")

	flag.Parse()

	if *path != "" && *uci != "" {
		log.Fatal("-config and -uci are mutually exclusive")
	}
	cfg := proxy.DefaultConfig()
	if *path != "" {
		loaded, err := proxy.LoadConfig(*path)
		if err != nil {log.Fatalf("invalid configuration: %v",err)}
		cfg = loaded
	} else if *uci != "" {
		loaded, err := proxy.LoadUCI(*uci)
		if err != nil {log.Fatalf("invalid UCI configuration: %v",err)}
		cfg = loaded
	}
	if *listen!="" {cfg.Listen=*listen}
	s,err:=proxy.NewWithConfig(cfg)
	if err!=nil {log.Fatalf("configuration rejected: %v",err)}
    if *syncSubscriptions!="" {
        if err:=proxy.SyncSubscriptions(cfg,*syncSubscriptions);err!=nil{log.Fatalf("subscription update rejected: %v",err)}
        fmt.Println("eproxy subscription cache updated")
        return
    }
	if *export!="" {
        if err:=proxy.WriteSingBoxConfig(*export,cfg,*providerCache);err!=nil {log.Fatalf("sing-box export rejected: %v",err)}
        fmt.Println("eproxy sing-box config exported")
        return
    }
	if *checkConfig {
		fmt.Println("eproxy configuration valid")
		return
	}
    if cfg.Engine=="singbox" {
        log.Fatal("engine singbox must be launched through OpenWrt procd after export and sing-box check; native mode cannot implement QUIC")
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
