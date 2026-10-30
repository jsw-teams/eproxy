package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fullUCI = `config eproxy 'main'
	option enabled '1'
	option listen '127.0.0.1:1080'
	option default_outbound 'secure'
	option dial_timeout_seconds '12'
	option username 'owner'
	option password 'secret#inside'

config outbound 'direct'
	option type 'direct'

config outbound 'secure'
	option type 'trojan'
	option address 'example.net:443'
	option server_name 'example.net'
	option password 'test password'

config outbound 'vless1'
	option type 'vless'
	option address 'vless.example:443'
	option server_name 'vless.example'
	option uuid '4e52614c-1e02-4527-9254-f6e8beeb53e8'

config rule
	option domain_suffix 'blocked.example'
	option outbound 'block'

config rule
	option domain_suffix 'example.org'
	option outbound 'direct'

config rule
	option domain_suffix 'proxy.example'
	option outbound 'secure'
`

func testUCIFile(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eproxy")
	if err := os.WriteFile(path, []byte(body), mode); err != nil { t.Fatal(err) }
	if err := os.Chmod(path, mode); err != nil { t.Fatal(err) }
	return path
}

func TestUICoreConfigWithCredentialsAndRules(t *testing.T) {
	path := testUCIFile(t, fullUCI, 0600)
	cfg, err := LoadUCI(path)
	if err != nil { t.Fatal(err) }
	if cfg.Listen != "127.0.0.1:1080" || cfg.DialTimeoutSeconds != 12 || cfg.Password != "secret#inside" {
		t.Fatalf("general UI settings not reflected in core: %#v", cfg)
	}
	if len(cfg.Outbounds) != 3 || cfg.Outbounds["vless1"].Type != "vless" {
		t.Errorf("protocol UI selection not reflected in core: %#v", cfg.Outbounds)
	}
	if len(cfg.Rules) != 3 { t.Fatalf("lost or reordered rules: %#v", cfg.Rules) }
	testRoutes := []struct{ host, want string; blocked bool }{
		{"blocked.example", "", true},
		{"sub.blocked.example", "", true},
		{"example.org", "direct", false},
		{"proxy.example", "trojan", false},
		{"other.example", "trojan", false},
	}
	for _, tc := range testRoutes {
		ob, blocked := cfg.OutboundFor(tc.host)
		if blocked != tc.blocked || (!blocked && ob.Type != tc.want) {
			t.Errorf("%s: type %s, blocked=%v", tc.host, ob.Type, blocked)
		}
	}
}

func TestUCIRejectsSecretsWithUnsafePermissions(t *testing.T) {
	path := testUCIFile(t, fullUCI, 0644)
	if _, err := LoadUCI(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected permission rejection, got %v", err)
	}
}

func TestUCIRejectsInvalidEdits(t *testing.T) {
	cases := map[string]string{
		"bad listen": strings.Replace(fullUCI, "127.0.0.1:1080", "0.0.0.0:1080", 1),
		"unsupported protocol": strings.Replace(fullUCI, "option type 'trojan'", "option type 'hysteria2'", 1),
		"unknown option": fullUCI + "\noption hidden 'value'\n",
		"missing outbound": strings.Replace(fullUCI, "option default_outbound 'secure'", "option default_outbound 'missing'", 1),
		"duplicate named outbound": fullUCI + "\nconfig outbound 'secure'\n\toption type 'direct'\n",
		"missing rule action": fullUCI + "\nconfig rule\n\toption domain_suffix 'oops.example'\n",
		"malformed quotes": fullUCI + "\nconfig rule\n\toption outbound 'missing\n",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			path := testUCIFile(t, data, 0600)
			if _, err := LoadUCI(path); err == nil { t.Fatal("invalid LuCI/UCI state silently accepted") }
		})
	}
}

func TestUIProtocolParity(t *testing.T) {
	viewPath := filepath.Join("..", "..", "package", "luci-app-eproxy", "htdocs",
		"luci-static", "resources", "view", "eproxy", "settings.js")
	data, err := os.ReadFile(viewPath)
	if err != nil { t.Fatal(err) }
	ui := string(data)
	for _, protocol := range []string{"direct", "http", "socks5", "trojan", "vless", "shadowsocks-aead", "hysteria2", "vless-reality", "shadowsocks-2022"} {
		if !strings.Contains(ui, "o.value('"+protocol+"'") {
			t.Errorf("UI does not offer compiled core protocol %q", protocol)
		}
	}
	for _, unsupported := range []string{"tuic", "shadowsocks-2022-udp-native", "vless-reality-native"} {
		if strings.Contains(ui, "o.value('"+unsupported+"'") {
			t.Errorf("UI improperly offers unimplemented protocol %q", unsupported)
		}
	}
}

func TestUCIExampleInstalledWithPackage(t *testing.T) {
	path := filepath.Join("..", "..", "package", "eproxy-core", "files", "eproxy.config")
	cfg, err := LoadUCI(path)
	if err != nil { t.Fatalf("installed UCI default must be valid: %v", err) }
	if cfg.DefaultOutbound != "direct" || cfg.Outbounds["direct"].Type != "direct" {
		t.Fatalf("bad installed package configuration %#v", cfg)
	}
}
