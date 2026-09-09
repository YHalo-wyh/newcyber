const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const root=path.join(__dirname,'..');
const read=(p)=>fs.readFileSync(path.join(root,p),'utf8');

test('specialized tool surface renderer and catalog stay syntactically valid',()=>{
  const surfaces=read('renderer/tool_surfaces.js');
  const catalog=read('renderer/tool_surface_catalog.js');
  assert.doesNotThrow(()=>new vm.Script(surfaces,{filename:'tool_surfaces.js'}));
  assert.doesNotThrow(()=>new vm.Script(catalog,{filename:'tool_surface_catalog.js'}));
});

test('toolbox loads specialized surface CSS and registry after tool UI but before workspace renderers',()=>{
  const html=read('renderer/toolbox.html');
  assert.match(html,/styles\/tool_surfaces\.css/);
  const toolUi=html.indexOf('tool_ui.js');
  const catalog=html.indexOf('tool_surface_catalog.js');
  const surfaces=html.indexOf('tool_surfaces.js');
  const workspace=html.indexOf('workspace_three_pane.js');
  assert.ok(toolUi>=0&&catalog>toolUi&&surfaces>catalog&&workspace>surfaces);
});

test('low-altitude tools get system-specific workbenches instead of one generic textarea layout',()=>{
  const js=read('renderer/tool_surfaces.js');
  const css=read('renderer/styles/tool_surfaces.css');
  for(const token of [
    'Ground Control Station','Companion Computer','Flight Controller','Camera / ROS',
    "'mavlink-hex'","'mavlink-signature-verify'","'uav-wifi-evidence'","'uav-flight-log'",
    "'uav-gnss-audit'","'uav-gnss-spectrum'","'uav-regulatory-audit'","'firmware-update-audit'"
  ]) assert.match(js,new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.match(js,/mav-frame-guide/);
  assert.match(js,/api-request-line/);
  assert.match(js,/gnss-route-map/);
  assert.match(js,/flight-recorder-strip/);
  assert.match(js,/update-chain-rail/);
  assert.match(css,/\.uav-system-layout/);
  assert.match(css,/\.wifi-topology/);
  assert.match(css,/\.gnss-route-map/);
  assert.match(css,/\.surface-workbench/);
});

test('surface catalog restores low-altitude tools that later renderer layers may hide',()=>{
  const source=read('renderer/tool_surface_catalog.js');
  const sandbox={
    DOMAINS:{lowalt:{tools:[['uav-recon-analyze','Recon','x']]}},
    TOOL_META:{
      'uav-recon-analyze':{domain:'lowalt',title:'Recon',label:'x'},
      'mavlink-hex':{domain:'lowalt',title:'MAVLink',label:'hex'},
      'nmea-analyze':{domain:'lowalt',title:'NMEA',label:'nmea'},
      'ai-source-scan':{domain:'ai',title:'AI',label:'code'}
    }
  };
  vm.runInNewContext(source,sandbox);
  const ids=sandbox.DOMAINS.lowalt.tools.map((row)=>row[0]);
  assert.ok(ids.includes('mavlink-hex'));
  assert.ok(ids.includes('nmea-analyze'));
  assert.equal(ids.includes('ai-source-scan'),false);
  assert.equal(ids.filter((id)=>id==='uav-recon-analyze').length,1);
});

test('specialized surfaces keep the existing offline tool contract through a hidden payload bridge',()=>{
  const js=read('renderer/tool_surfaces.js');
  assert.match(js,/id="tool-input" class="surface-hidden-input"/);
  assert.match(js,/data-action="run-tool"/);
  assert.match(js,/syncPayload/);
  assert.match(js,/离线解析 · 不主动连接目标/);
});
