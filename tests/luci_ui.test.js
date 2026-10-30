// Execute the actual LuCI view in a simulated form/rpc runtime.
// This tests the behavior of the view, not merely the presence of strings.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const file = path.join(__dirname, '..', 'package', 'luci-app-eproxy',
  'htdocs', 'luci-static', 'resources', 'view', 'eproxy', 'settings.js');
const source = fs.readFileSync(file, 'utf8');
const sections = [];
class Option {
  constructor(section, id) {
    this.section = section;
    this.id = id;
    this.values = [];
    this.dependencies = [];
  }
  value(v) { this.values.push(v); }
  depends(prop, v) { this.dependencies.push([prop,v]); }
}
class Section {
  constructor(type,name,sectionType) {
    this.type = type;
    this.name = name;
    this.sectionType = sectionType;
    this.options = [];
    sections.push(this);
  }
  option(klass, id) {
    const item = new Option(this, id);
    item.klass = klass;
    this.options.push(item);
    return item;
  }
}
const form = {
  NamedSection:'NamedSection',GridSection:'GridSection',Flag:'Flag',
  DummyValue:'DummyValue', Value:'Value', ListValue:'ListValue',
  Map: class Map {
    constructor(name) { this.name = name; }
    section(klass, name, type) { return new Section(klass,name,type); }
    render() { return Promise.resolve({ sections }); }
  }
};
const view = {extend: (impl) => impl};
const rpc = {
  declare: ({object,method,params})=>{
    assert.equal(object,'service');
    assert.equal(method,'list');
    assert.deepEqual(params,['name']);
    return (name)=>Promise.resolve({
      [name]: {instances:{eproxy:{running:true}}}
    });
  }
};
const uci = {
  load:(name)=>{assert.equal(name,'eproxy');return Promise.resolve({});},
  sections:(name,type)=>{assert.equal(name,'eproxy');assert.equal(type,'outbound');return [{'.name':'direct'},{'.name':'secure'}];}
};
const L = {resolveDefault:(p,def)=>Promise.resolve(p).catch(()=>def)};
const translate=(s)=>s;
const compile = new Function('view','form','rpc','uci','L','_',source);
const luciView = compile(view,form,rpc,uci,L,translate);
assert.ok(luciView && typeof luciView.load==='function');
(async()=>{
  const data = await luciView.load();
  await luciView.render(data);
  const general = sections.find(s=>s.name==='main');
  const outbounds = sections.find(s=>s.name==='outbound');
  const rules = sections.find(s=>s.name==='rule');
  assert.ok(general && outbounds && rules, 'all three functional management sections must be present');
  assert.equal(general.type,'NamedSection');
  assert.equal(outbounds.type,'GridSection');
  assert.equal(rules.type,'GridSection');
  assert.equal(outbounds.addremove,true);
  assert.equal(rules.addremove,true);
  assert.equal(rules.sortable,true);
  const ids=(s)=>new Set(s.options.map(o=>o.id));
  for(const field of ['_status','enabled','listen','username','password','default_outbound','dial_timeout_seconds'])
    assert.ok(ids(general).has(field), 'general control missing: '+field);
  const status = general.options.find(o=>o.id==='_status');
  assert.equal(status.cfgvalue(),'Running');
  const supported = ['direct','http','socks5','trojan','vless','shadowsocks-aead'];
  const protocol = outbounds.options.find(o=>o.id==='type');
  assert.deepEqual(protocol.values,supported,'view and Go parser supported protocol sets must stay in sync');
  for(const field of ['type','address','username','password','server_name','ca_file','uuid'])
    assert.ok(ids(outbounds).has(field), 'node control missing: '+field);
  for(const field of ['domain_suffix','outbound'])
    assert.ok(ids(rules).has(field), 'routing control missing: '+field);
  assert.ok(rules.options.find(o=>o.id==='outbound').values.includes('secure'));
  assert.ok(general.options.find(o=>o.id==='default_outbound').values.includes('secure'));
  assert.equal(general.options.find(o=>o.id==='password').password,true);
  assert.equal(outbounds.options.find(o=>o.id==='password').password,true);
  console.log('LuCI integration contract passed: general, status, node CRUD, protocols, rule order and secrets');
})().catch(e=>{console.error(e);process.exitCode=1;});
