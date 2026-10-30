package proxy

import (
	"encoding/json"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

type Config struct {
	Listen string `json:"listen"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	DefaultOutbound string `json:"default_outbound"`
	Outbounds map[string]Outbound `json:"outbounds"`
	Rules []Rule `json:"rules,omitempty"`
	DialTimeoutSeconds int `json:"dial_timeout_seconds,omitempty"`
}
type Outbound struct {
	Type string `json:"type"` // direct, http, socks5, trojan, shadowsocks-aead, vless
	Address string `json:"address,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	CAFile string `json:"ca_file,omitempty"`
	UUID string `json:"uuid,omitempty"`
}
type Rule struct {
	DomainSuffix string `json:"domain_suffix"`
	Outbound string `json:"outbound"` // outbound name or "block"
}

func DefaultConfig() Config {
	return Config{
		Listen: "127.0.0.1:1080",
		DefaultOutbound: "direct",
		Outbounds: map[string]Outbound{"direct": {Type:"direct"}},
		DialTimeoutSeconds: 10,
	}
}
func LoadConfig(path string) (Config, error) {
	f,err:=os.Open(path)
	if err!=nil { return Config{},err }
	defer f.Close()
	dec:=json.NewDecoder(io.LimitReader(f,64*1024+1))
	dec.DisallowUnknownFields()
	var c Config
	if err:=dec.Decode(&c);err!=nil{return Config{},fmt.Errorf("invalid eproxy JSON: %w",err)}
	var trailing interface{}
	if err:=dec.Decode(&trailing);!errors.Is(err,io.EOF) { return Config{},errors.New("config must be one JSON document") }
	if err:=c.Validate();err!=nil{return Config{},err}
	// Avoid exposing outbound proxy credentials through group/world-readable files.
	if c.hasSecrets() {
		st,err:=os.Stat(path)
		if err!=nil{return Config{},err}
		if st.Mode().Perm()&0077!=0 {
			return Config{},errors.New("credential-bearing eproxy JSON must be chmod 0600")
		}
	}
	return c,nil
}
func loopbackAddr(addr string) bool {
	host,port,err:=net.SplitHostPort(addr)
	if err!=nil || port=="" || port=="0" {return false}
	p,err:=net.LookupPort("tcp",port)
	if err!=nil || p<1 || p>65535 {return false}
	if strings.EqualFold(host,"localhost") {return true}
	ip:=net.ParseIP(host)
	return ip!=nil && ip.IsLoopback()
}
func validRemote(addr string) bool {
	h,p,err:=net.SplitHostPort(addr)
	if err!=nil || h=="" {return false}
	port,err:=net.LookupPort("tcp",p)
	return err==nil && port>0 && port<65536
}
func (c Config) hasSecrets()bool {
	if c.Username!="" || c.Password!="" {return true}
	for _,ob:=range c.Outbounds {
		if ob.Password!="" || ob.Username!="" || ob.UUID!="" {return true}
	}
	return false
}

func (c *Config) Validate() error {
	if !loopbackAddr(c.Listen) {return errors.New("listener must be an explicit loopback TCP host:port")}
	if (c.Username=="")!=(c.Password=="") {return errors.New("listener username and password must both be set or neither")}
	if c.DialTimeoutSeconds==0 {c.DialTimeoutSeconds=10}
	if c.DialTimeoutSeconds<1 || c.DialTimeoutSeconds>120 {return errors.New("dial timeout must be 1..120 seconds")}
	if c.Outbounds==nil {c.Outbounds=map[string]Outbound{"direct":{Type:"direct"}}}
	if c.DefaultOutbound=="" {c.DefaultOutbound="direct"}
	if len(c.Outbounds)>32 {return errors.New("too many outbounds")}
	for name,ob:=range c.Outbounds {
		if name=="" || name=="block" {return fmt.Errorf("invalid outbound name %q",name)}
		switch ob.Type {
		case "direct":
			if ob.Address!="" {return fmt.Errorf("%s: direct has no server",name)}
		case "http","socks5":
			if !validRemote(ob.Address) {return fmt.Errorf("%s: invalid upstream address",name)}
			if (ob.Username=="")!=(ob.Password=="") {return fmt.Errorf("%s: upstream credentials incomplete",name)}
			if ob.Username!="" && !loopbackAddr(ob.Address) {
				return fmt.Errorf("%s: plaintext upstream credentials may only be sent to loopback",name)
			}
		case "trojan":
			if !validRemote(ob.Address) || ob.Password=="" || ob.ServerName=="" {return fmt.Errorf("%s: trojan requires address, password and verified TLS server_name",name)}
		case "shadowsocks-aead":
			key,err:=base64.StdEncoding.DecodeString(ob.Password)
			if !validRemote(ob.Address) || err!=nil || len(key)!=32 {return fmt.Errorf("%s: Shadowsocks AES-256-GCM requires remote address and base64 32-byte key",name)}
		case "vless":
			_,err:=parseUUID(ob.UUID)
			if !validRemote(ob.Address) || ob.ServerName=="" || err!=nil {return fmt.Errorf("%s: VLESS requires address, UUID and TLS server_name",name)}
		default:
			return fmt.Errorf("%s: unsupported outbound type %q",name,ob.Type)
		}
	}
	if _,ok:=c.Outbounds[c.DefaultOutbound];!ok{return fmt.Errorf("default outbound %q missing",c.DefaultOutbound)}
	if len(c.Rules)>128 {return errors.New("too many routing rules")}
	for _,r:=range c.Rules {
		if r.DomainSuffix=="" || strings.ContainsAny(r.DomainSuffix," /:\t\r\n") {return fmt.Errorf("invalid domain suffix %q",r.DomainSuffix)}
		if r.Outbound!="block" {
			if _,ok:=c.Outbounds[r.Outbound];!ok {return fmt.Errorf("route outbound %q missing",r.Outbound)}
		}
	}
	return nil
}
func (c Config) Deadline() time.Duration {return time.Duration(c.DialTimeoutSeconds)*time.Second}
func (c Config) OutboundFor(host string) (Outbound,bool) {
	host=strings.TrimSuffix(strings.ToLower(host),".")
	for _,r:=range c.Rules {
		suffix:=strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(r.DomainSuffix),"."),".")
		if host==suffix || strings.HasSuffix(host,"."+suffix) {
			if r.Outbound=="block" {return Outbound{},true}
			return c.Outbounds[r.Outbound],false
		}
	}
	return c.Outbounds[c.DefaultOutbound],false
}
