'use strict';
'require view';
'require form';
'require rpc';
'require uci';

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(callServiceList('eproxy'), {}),
			uci.load('eproxy')
		]);
	},

	render: function(data) {
		var services = data[0] || {};
		var svc = services.eproxy || {};
		var instances = svc.instances || {};
		var running = Object.keys(instances).some(function(key) {
			return instances[key] && instances[key].running === true;
		});
		var knownNodes = uci.sections('eproxy', 'outbound') || [];
		var m = new form.Map('eproxy', _('eproxy — Proxy Manager'),
			_('Configure the local proxy, outbounds and ordered domain rules. ' +
			  'Save & Apply to reload the procd service. Settings are shared with the Go daemon via UCI. ' +
			  'The listener is loopback only, not a LAN transparent proxy.'));

		var s = m.section(form.NamedSection, 'main', 'eproxy', _('Service & authentication'));
		s.addremove = false;

		var o = s.option(form.DummyValue, '_status', _('Service status'));
		o.cfgvalue = function() {
			return running ? _('Running') : _('Stopped / unavailable');
		};

		o = s.option(form.ListValue, 'engine', _('Execution engine'));
		o.value('native', _('eproxy native (basic protocols)'));
		o.value('singbox', _('sing-box (Hysteria2 / REALITY / SS2022 / TUN / UDP)'));
		o.default = 'native';
		o.rmempty = false;

		o = s.option(form.Flag, 'enable_tun', _('Transparent TUN on br-lan'));
		o.default = o.disabled;
		o.depends('engine', 'singbox');
		o.description = _('Requires kmod-tun, nftables, and a validated sing-box binary. WAN is excluded.');

		o = s.option(form.ListValue, 'dns_strategy', _('DNS / IPv6 policy'));
		['prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only'].forEach(function(v) { o.value(v, v); });
		o.default = 'prefer_ipv4';

		o = s.option(form.Value, 'dns_remote', _('Upstream DNS server IP'));
		o.default = '1.1.1.1';
		o.datatype = 'ipaddr';
		o.description = _('Proxy engine DNS resolver. Choose trusted IPv4 or IPv6 recursive server.');

		o = s.option(form.Value, 'tun_interface', _('Managed LAN interface'));
		o.depends('enable_tun', '1');
		o.default = 'br-lan';
		o.readonly = true;
		o.description = _('Only br-lan is supported to avoid intercepting WAN and router management traffic.');

		o = s.option(form.Flag, 'enabled', _('Enable eproxy'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.Value, 'listen', _('Listen address'));
		o.default = '127.0.0.1:1080';
		o.placeholder = '127.0.0.1:1080';
		o.rmempty = false;
		o.description = _('Only 127.0.0.1 and [::1] are permitted. Do not publish an unauthenticated proxy to LAN or WAN.');

		o = s.option(form.Value, 'username', _('Inbound username'));
		o.description = _('Set both username and password to require Basic and SOCKS5 authentication.');

		o = s.option(form.Value, 'password', _('Inbound password'));
		o.password = true;

		o = s.option(form.Value, 'default_outbound', _('Default outbound'));
		o.value('direct', _('Direct'));
		knownNodes.forEach(function(node) { o.value(node['.name'], node['.name']); });
		o.default = 'direct';
		o.rmempty = false;
		o.description = _('Enter the section ID of an outbound below. "direct" is installed by default.');

		o = s.option(form.Value, 'dial_timeout_seconds', _('Connection timeout (seconds)'));
		o.datatype = 'range(1,120)';
		o.default = '10';
		o.rmempty = false;

		s = m.section(form.GridSection, 'outbound', _('Outbound nodes'),
			_('Add named nodes using the supported protocol types. ' +
			  'TLS certificate checking is mandatory, and keys are stored in root-only UCI configuration. ' +
			  'Unsupported transports (REALITY, Hysteria2, SS-2022 and QUIC) are intentionally not selectable.'));
		s.anonymous = false;
		s.addremove = true;
		s.sortable = false;
		s.nodescriptions = true;

		o = s.option(form.ListValue, 'type', _('Protocol'));
		o.value('direct', _('Direct'));
		o.value('http', _('HTTP CONNECT upstream'));
		o.value('socks5', _('SOCKS5 upstream'));
		o.value('trojan', _('Trojan over verified TLS'));
		o.value('vless', _('VLESS TCP over verified TLS'));
		o.value('shadowsocks-aead', _('Shadowsocks AES-256-GCM (not 2022)'));
		o.value('hysteria2', _('Hysteria2 (QUIC, sing-box engine)'));
		o.value('vless-reality', _('VLESS REALITY (sing-box engine)'));
		o.value('shadowsocks-2022', _('Shadowsocks-2022 (sing-box engine)'));
		o.rmempty = false;
		o.editable = true;

		o = s.option(form.Value, 'address', _('Remote address (host:port)'));
		['http', 'socks5', 'trojan', 'vless', 'shadowsocks-aead', 'hysteria2', 'vless-reality', 'shadowsocks-2022'].forEach(function(t) { o.depends('type', t); });
		o.placeholder = 'example.com:443';
		o.modalonly = true;

		o = s.option(form.Value, 'server_name', _('TLS server name (SNI)'));
		o.depends('type', 'trojan');
		o.depends('type', 'vless');
		o.depends('type', 'vless-reality');
		o.depends('type', 'hysteria2');
		o.modalonly = true;

		o = s.option(form.Value, 'username', _('Upstream username'));
		o.depends('type', 'http');
		o.depends('type', 'socks5');
		o.modalonly = true;

		o = s.option(form.Value, 'password', _('Upstream secret / Shadowsocks base64 key'));
		o.password = true;
		['http', 'socks5', 'trojan', 'shadowsocks-aead', 'hysteria2', 'vless-reality', 'shadowsocks-2022'].forEach(function(t) { o.depends('type', t); });
		o.modalonly = true;
		o.description = _('Shadowsocks AES-256-GCM requires a base64-encoded 32-byte key. Plaintext proxy credentials are only accepted for loopback upstream servers.');

		o = s.option(form.Value, 'uuid', _('VLESS UUID'));
		o.depends('type', 'vless');
		o.depends('type', 'vless-reality');
		o.modalonly = true;

		o = s.option(form.Value, 'method', _('Shadowsocks-2022 cipher'));
		['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'].forEach(function(v) {
			o.value(v, v);
		});
		o.depends('type', 'shadowsocks-2022');
		o.modalonly = true;

		o = s.option(form.Value, 'reality_public_key', _('REALITY server public key'));
		o.depends('type', 'vless-reality');
		o.modalonly = true;
		o = s.option(form.Value, 'reality_short_id', _('REALITY short ID'));
		o.depends('type', 'vless-reality');
		o.modalonly = true;

		o = s.option(form.Value, 'obfs_password', _('Hysteria2 Salamander password (optional)'));
		o.depends('type', 'hysteria2');
		o.password = true;
		o.modalonly = true;

		o = s.option(form.Value, 'ca_file', _('Optional CA PEM path'));
		o.depends('type', 'trojan');
		o.depends('type', 'vless');
		o.modalonly = true;
		o.description = _('A file on the router, not a private key. A matching valid TLS certificate is always required.');

		s = m.section(form.GridSection, 'rule', _('Routing rules (top to bottom)'),
			_('The first matching domain suffix wins. Block rules reject CONNECT and discard unsupported UDP. ' +
			  'Newly added outbound names can be entered below.'));
		s.anonymous = true;
		s.addremove = true;
		s.sortable = true;
		s.nodescriptions = true;

		o = s.option(form.Value, 'domain_suffix', _('Domain suffix'));
		o.rmempty = false;
		o.placeholder = 'example.com';

		o = s.option(form.Value, 'outbound', _('Action / outbound name'));
		o.value('block', _('Block'));
		knownNodes.forEach(function(node) { o.value(node['.name'], node['.name']); });
		o.rmempty = false;
		o.placeholder = 'direct';
		o.description = _('Use a named outbound or "block". Rules apply only to destination names available to eproxy; no DNS interception is performed.');

		s = m.section(form.GridSection, 'subscription', _('HTTPS subscriptions'),
			_('Only HTTPS sing-box JSON outbound collections are accepted. Provider URLs and secrets remain private. ' +
			  'Save & Apply reloads eproxy and refreshes the provider cache if sing-box is enabled.'));
		s.anonymous = false;
		s.addremove = true;
		s.sortable = false;

		o = s.option(form.Value, 'url', _('Provider HTTPS URL'));
		o.rmempty = false;
		o.placeholder = 'https://provider.example/nodes.json';
		o.description = _('Must resolve to public IPs via HTTPS on port 443; redirects and local addresses are refused.');

		return m.render();
	}
});
