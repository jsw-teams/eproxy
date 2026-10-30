package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// LoadUCI parses the deliberately restricted UCI schema shared with LuCI.
// No shell is executed and unknown section types/keys fail closed.
func LoadUCI(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil { return Config{}, err }
	defer f.Close()
	cfg := DefaultConfig()
	cfg.Outbounds = make(map[string]Outbound)
	cfg.Rules = nil
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 64*1024)
	sectionType, name := "", ""
	var rule Rule
    var subscription Subscription
	seen := make(map[string]bool)
	foundMain := false
	lineNo := 0
	closeSection := func() error {
		if sectionType == "subscription" {
            if subscription.Name=="" || subscription.URL=="" {return errors.New("subscription needs URL and name")}
            cfg.Subscriptions=append(cfg.Subscriptions,subscription)
        }
        if sectionType == "rule" {
			if rule.DomainSuffix == "" || rule.Outbound == "" {
				return errors.New("rule requires domain_suffix and outbound")
			}
			cfg.Rules = append(cfg.Rules, rule)
		}
		return nil
	}
	for scan.Scan() {
		lineNo++
		words, err := uciWords(scan.Text())
		if err != nil { return Config{}, fmt.Errorf("UCI line %d: %w", lineNo, err) }
		if len(words) == 0 { continue }
		fail := func(msg string) (Config, error) { return Config{}, fmt.Errorf("UCI line %d: %s", lineNo, msg) }
		switch words[0] {
		case "config":
			if len(words) < 2 || len(words) > 3 { return fail("invalid config statement") }
			if err := closeSection(); err != nil { return fail(err.Error()) }
			sectionType, name = words[1], ""
			if len(words) == 3 { name = words[2] }
			switch sectionType {
			case "eproxy":
				if name != "main" || foundMain { return fail("expected exactly one config eproxy 'main'") }
				foundMain = true
			case "outbound":
				if name == "" || name == "block" || strings.ContainsAny(name, " \t\r\n") { return fail("invalid outbound name") }
				if _,exists := cfg.Outbounds[name]; exists { return fail("duplicate outbound section") }
				cfg.Outbounds[name] = Outbound{}
			case "subscription":
                if name=="" {return fail("subscription requires section name")}
                subscription=Subscription{Name:name}
            case "rule":
                if name != "" { return fail("rule sections must be anonymous") }
				rule = Rule{}
			default: return fail("unknown section type " + sectionType)
			}
			seen = make(map[string]bool)
		case "option":
			if sectionType == "" || len(words) != 3 { return fail("invalid option statement") }
			key, value := words[1], words[2]
			if seen[key] { return fail("duplicate option " + key) }
			seen[key] = true
			switch sectionType {
			case "eproxy":
				switch key {
				case "enabled": if value != "0" && value != "1" { return fail("invalid enabled flag") }
				case "engine": cfg.Engine=value
                case "enable_tun": if value!="0" && value!="1" {return fail("invalid enable_tun flag")};cfg.EnableTUN=value=="1"
                case "dns_strategy": cfg.DNSStrategy=value
                case "dns_remote": cfg.DNSRemote=value
                case "dns_server_name": cfg.DNSServerName=value
                case "tun_interface": cfg.TUNInterface=value
                case "listen": cfg.Listen = value
				case "username": cfg.Username = value
				case "password": cfg.Password = value
				case "default_outbound": cfg.DefaultOutbound = value
				case "dial_timeout_seconds":
					n,e := strconv.Atoi(value); if e != nil { return fail("invalid dial timeout") }; cfg.DialTimeoutSeconds = n
				default: return fail("unsupported main option " + key)
				}
			case "outbound":
				ob := cfg.Outbounds[name]
				switch key {
				case "method": ob.Method=value
                case "reality_public_key":ob.RealityPublicKey=value
                case "reality_short_id":ob.RealityShortID=value
                case "obfs_password":ob.ObfsPassword=value
                case "type": ob.Type = value
				case "address": ob.Address = value
				case "username": ob.Username = value
				case "password": ob.Password = value
				case "server_name": ob.ServerName = value
				case "ca_file": ob.CAFile = value
				case "uuid": ob.UUID = value
				default: return fail("unsupported outbound option " + key)
				}
				cfg.Outbounds[name] = ob
			case "subscription":
                switch key {
                case "url":subscription.URL=value
                default:return fail("unsupported subscription option "+key)
                }
            case "rule":
                switch key {
				case "domain_suffix": rule.DomainSuffix = value
				case "outbound": rule.Outbound = value
				default: return fail("unsupported rule option " + key)
				}
			}
		default: return fail("only config and option are permitted")
		}
	}
	if err := scan.Err(); err != nil { return Config{}, err }
	if !foundMain { return Config{}, errors.New("UCI main section missing") }
	if err := closeSection(); err != nil { return Config{}, err }
	if err := cfg.Validate(); err != nil { return Config{}, err }
	if cfg.hasSecrets() {
		st, err := os.Stat(path); if err != nil { return Config{}, err }
		if st.Mode().Perm() & 0077 != 0 { return Config{}, errors.New("UCI credentials require file mode 0600") }
	}
	return cfg, nil
}

// uciWords implements basic OpenWrt UCI quoting (single/double quotes),
// escaped quote/backslash and comments outside quoted strings.
func uciWords(line string) ([]string, error) {
	var result []string
	var b strings.Builder
	quote := rune(0)
	escape := false
	started := false
	flush := func() { if started { result = append(result, b.String()); b.Reset(); started = false } }
	for _, r := range line {
		if escape {
			if r != '\\' && r != '\'' && r != '"' && r != '#' && r != ' ' {
				b.WriteRune('\\')
			}
			b.WriteRune(r); escape = false; started = true; continue
		}
		if r == '\\' { escape = true; started = true; continue }
		if quote != 0 {
			if r == quote { quote = 0 } else { b.WriteRune(r) }
			started = true; continue
		}
		if r == '\'' || r == '"' { quote = r; started = true; continue }
		if r == '#' { break }
		if r == ' ' || r == '\t' || r == '\r' { flush(); continue }
		b.WriteRune(r); started = true
	}
	if quote != 0 || escape { return nil, errors.New("unterminated UCI quote or escape") }
	flush()
	return result, nil
}
