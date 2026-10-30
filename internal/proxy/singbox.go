package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
    "path/filepath"
	"sort"
	"strconv"
	"strings"
)

// SingBoxDocument generates the actual runtime configuration for sing-box.
// It leverages maintained protocol/QUIC/REALITY implementations rather than
// inventing cryptographic or QUIC behavior in the eproxy control plane.
// Final deployment must also pass "sing-box check -c" on the target release.
func SingBoxDocument(cfg Config) ([]byte, error) {
	if cfg.Engine != "singbox" {
		return nil, errors.New("select engine=singbox to export sing-box config")
	}
	if err := cfg.Validate(); err != nil { return nil, err }
	host, portStr, err := net.SplitHostPort(cfg.Listen)
	if err != nil { return nil, err }
	port, err := strconv.Atoi(portStr)
	if err != nil { return nil, err }
	mixed := map[string]interface{}{
		"type":"mixed","tag":"eproxy-local","listen":host,"listen_port":port,
	}
	if cfg.Username != "" {
		mixed["users"]=[]map[string]string{{"username":cfg.Username,"password":cfg.Password}}
	}
	inbounds := []map[string]interface{}{mixed}
	if cfg.EnableTUN {
		inbounds=append(inbounds,map[string]interface{}{
			"type":"tun","tag":"eproxy-tun","interface_name":"eproxy0",
			"address":[]string{"172.19.0.1/30","fdfe:dcba:9876::1/126"},
			"auto_route":true,"auto_redirect":true,"strict_route":true,
			"include_interface":[]string{cfg.TUNInterface},
		})
	}
	outbounds := make([]map[string]interface{},0,len(cfg.Outbounds)+1)
	names:=make([]string,0,len(cfg.Outbounds))
	for name:=range cfg.Outbounds {names=append(names,name)}
	sort.Strings(names)
	hasDirect:=false
	for _,name:=range names {
		ob:=cfg.Outbounds[name]
		entry,err:=singBoxOutbound(name,ob)
		if err!=nil{return nil,err}
		if name=="direct" && ob.Type=="direct" {hasDirect=true}
		outbounds=append(outbounds,entry)
	}
	if !hasDirect {
		if _,exists:=cfg.Outbounds["eproxy-direct"];exists {return nil,errors.New("eproxy-direct reserved")}
		outbounds=append(outbounds,map[string]interface{}{"type":"direct","tag":"eproxy-direct"})
	}
	direct:="eproxy-direct"
	if hasDirect {direct="direct"}
	rules:=make([]map[string]interface{},0,len(cfg.Rules)+3)
	if cfg.EnableTUN {
		rules=append(rules,map[string]interface{}{"protocol":"dns","action":"hijack-dns"})
		rules=append(rules,map[string]interface{}{"ip_is_private":true,"action":"route","outbound":direct})
	}
	for _,rule:=range cfg.Rules {
		suffix:=strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(rule.DomainSuffix),"."),".")
		if suffix=="" {return nil,errors.New("empty route suffix")}
		entry:=map[string]interface{}{"domain_suffix":[]string{suffix}}
		if rule.Outbound=="block" {entry["action"]="reject"} else {
			entry["action"]="route";entry["outbound"]=rule.Outbound
		}
		rules=append(rules,entry)
	}
	doc:=map[string]interface{}{
		"log":map[string]interface{}{"level":"warn","timestamp":true},
		"inbounds":inbounds,"outbounds":outbounds,
		"route":map[string]interface{}{
			"rules":rules,"final":cfg.DefaultOutbound,"auto_detect_interface":true,
		},
		"dns":map[string]interface{}{
			"servers":[]map[string]interface{}{
				{"type":"udp","tag":"eproxy-dns","server":cfg.DNSRemote},
			},
			"final":"eproxy-dns","strategy":cfg.DNSStrategy,
		},
	}
	return json.MarshalIndent(doc,"","  ")
}

func singBoxOutbound(tag string,o Outbound)(map[string]interface{},error) {
	out:=map[string]interface{}{"tag":tag}
	server,portText,err:=net.SplitHostPort(o.Address)
	port,_:=strconv.Atoi(portText)
	switch o.Type {
	case "direct":
		out["type"]="direct"
		return out,nil
	case "http","socks5","trojan","vless","vless-reality","hysteria2","shadowsocks-aead","shadowsocks-2022":
		if err!=nil || server=="" || port<=0 || port>65535 {
			return nil,fmt.Errorf("%s: invalid remote host:port",tag)
		}
		out["server"]=server;out["server_port"]=port
	default:
		return nil,fmt.Errorf("%s: unsupported sing-box protocol %q",tag,o.Type)
	}
	tlsOpt:=func()map[string]interface{}{
		return map[string]interface{}{"enabled":true,"server_name":o.ServerName}
	}
	switch o.Type {
	case "http","socks5":
		if o.Type=="socks5" {out["type"]="socks"} else {out["type"]="http"}
		if o.Username!="" {out["username"]=o.Username;out["password"]=o.Password}
	case "trojan":
		out["type"]="trojan";out["password"]=o.Password;out["tls"]=tlsOpt()
	case "vless","vless-reality":
		out["type"]="vless";out["uuid"]=o.UUID
		tls:=tlsOpt()
		if o.Type=="vless-reality" {
			tls["reality"]=map[string]interface{}{
				"enabled":true,"public_key":o.RealityPublicKey,"short_id":o.RealityShortID,
			}
		}
		out["tls"]=tls
	case "hysteria2":
		out["type"]="hysteria2";out["password"]=o.Password;out["tls"]=tlsOpt()
		if o.ObfsPassword!="" {
			out["obfs"]=map[string]string{"type":"salamander","password":o.ObfsPassword}
		}
	case "shadowsocks-2022","shadowsocks-aead":
		out["type"]="shadowsocks";out["password"]=o.Password
		if o.Type=="shadowsocks-2022" {out["method"]=o.Method} else {out["method"]="aes-256-gcm"}
	}
	return out,nil
}

// WriteSingBoxConfig never prints secret node credentials to logs; writes
// to an explicitly private file with a same-directory atomic rename.
func WriteSingBoxConfig(path string,cfg Config, providerPath string)error{
	data,err:=SingBoxDocument(cfg)
	if err!=nil{return err}
    if providerPath!="" {
        snap,e:=ReadProviders(providerPath)
        if e!=nil{return e}
        var doc map[string]interface{}
        if e=json.Unmarshal(data,&doc);e!=nil{return e}
        existing:=doc["outbounds"].([]interface{})
        known:=make(map[string]bool)
        for _,raw:=range existing {
            ob:=raw.(map[string]interface{})
            known[ob["tag"].(string)]=true
        }
        for _,node:=range snap.Outbounds {
            tag:=node["tag"].(string)
            if known[tag] {return fmt.Errorf("duplicate subscription tag %s",tag)}
            known[tag]=true
            existing=append(existing,node)
        }
        doc["outbounds"]=existing
        data,e=json.MarshalIndent(doc,"","  ")
        if e!=nil{return e}
    }
    return writePrivate(path,data)
}
func writePrivate(path string,data []byte)error {
	tmp,err:=os.CreateTemp(filepath.Dir(path),".eproxy-*.json")
	if err!=nil{return err}
	defer os.Remove(tmp.Name())
	if err=tmp.Chmod(0600);err!=nil{tmp.Close();return err}
	if _,err=tmp.Write(data);err!=nil{tmp.Close();return err}
	if err=tmp.Close();err!=nil{return err}
	return os.Rename(tmp.Name(),path)
}
