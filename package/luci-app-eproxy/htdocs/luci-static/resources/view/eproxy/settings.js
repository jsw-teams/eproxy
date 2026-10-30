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
		o.rmempty = false;
		o.editable = true;

		o = s.option(form.Value, 'address', _('Remote address (host:port)'));
		['http', 'socks5', 'trojan', 'vless', 'shadowsocks-aead'].forEach(function(t) { o.depends('type', t); });
		o.placeholder = 'example.com:443';
		o.modalonly = true;

		o = s.option(form.Value, 'server_name', _('TLS server name (SNI)'));
		o.depends('type', 'trojan');
		o.depends('type', 'vless');
		o.modalonly = true;

		o = s.option(form.Value, 'username', _('Upstream username'));
		o.depends('type', 'http');
		o.depends('type', 'socks5');
		o.modalonly = true;

		o = s.option(form.Value, 'password', _('Upstream secret / Shadowsocks base64 key'));
		o.password = true;
		['http', 'socks5', 'trojan', 'shadowsocks-aead'].forEach(function(t) { o.depends('type', t); });
		o.modalonly = true;
		o.description = _('Shadowsocks AES-256-GCM requires a base64-encoded 32-byte key. Plaintext proxy credentials are only accepted for loopback upstream servers.');

		o = s.option(form.Value, 'uuid', _('VLESS UUID'));
		o.depends('type', 'vless');
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
		o.rmempty = false;
		o.placeholder = 'direct';
		o.description = _('Use a named outbound or "block". Rules apply only to destination names available to eproxy; no DNS interception is performed.');

		return m.render();
	}
});
