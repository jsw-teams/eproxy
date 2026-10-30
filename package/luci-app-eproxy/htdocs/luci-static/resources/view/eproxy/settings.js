'use strict';
'require view';
'require form';

return view.extend({
	render: function() {
		var m = new form.Map('eproxy', _('eproxy'),
			_('Experimental local HTTP CONNECT and SOCKS5 proxy. ' +
			  'No transparent routing or encrypted upstream protocols are implemented yet.'));
		var s = m.section(form.NamedSection, 'main', 'eproxy', _('Service'));
		s.addremove = false;

		var o = s.option(form.Flag, 'enabled', _('Enable eproxy'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.Value, 'listen', _('Local listen address'));
		o.default = '127.0.0.1:1080';
		o.rmempty = false;
		o.description = _('Only loopback is permitted (no authentication).');
		return m.render();
	}
});
