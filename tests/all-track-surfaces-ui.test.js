const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const root=path.join(__dirname,'..');
const read=(p)=>fs.readFileSync(path.join(root,p),'utf8');

test('all-track specialized surface renderer and catalog compile',()=>{
  const renderer=read('renderer/track_surfaces.js');
  const catalog=read('renderer/track_surface_catalog.js');
  assert.doesNotThrow(()=>new vm.Script(renderer,{filename:'track_surfaces.js'}));
  assert.doesNotThrow(()=>new vm.Script(catalog,{filename:'track_surface_catalog.js'}));
});

test('toolbox loads all-track CSS and renderer after UAV surfaces but before workspace wrappers',()=>{
  const html=read('renderer/toolbox.html');
  assert.match(html,/styles\/track_surfaces\.css/);
  const uav=html.indexOf('tool_surfaces.js');
  const catalog=html.indexOf('track_surface_catalog.js');
  const tracks=html.indexOf('track_surfaces.js');
  const workspace=html.indexOf('workspace_three_pane.js');
  assert.ok(uav>=0&&catalog>uav&&tracks>catalog&&workspace>tracks);
});

test('vehicle surfaces expose bus heatmap and diagnostic session UI',()=>{
  const js=read('renderer/track_surfaces.js');
  const css=read('renderer/styles/track_surfaces.css');
  for(const token of ['vehicle-architecture','can-bus-strip','can-monitor','uds-session-rail','uds-flow','CAN / CANopen','UDS / ISO-TP']) assert.match(js,new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.match(css,/\.can-monitor/);
  assert.match(css,/\.uds-session-rail/);
});

test('AI surfaces separate pipeline prompt adversarial and dataset workflows',()=>{
  const js=read('renderer/track_surfaces.js');
  for(const token of ['ai-architecture','ai-pipeline-rail','prompt-flow','adv-builder','matrix-source-grid','data-table-head']) assert.match(js,new RegExp(token));
  assert.match(js,/preservedFileTools = new Set\(\['ai-model-scan'\]\)/);
});

test('Web3 surfaces expose calldata words EVM runtime and contract/account flows',()=>{
  const js=read('renderer/track_surfaces.js');
  const css=read('renderer/styles/track_surfaces.css');
  for(const token of ['web3-architecture','tx-builder','abi-word-guide','evm-runtime-rail','solana-account-rail','contract-call-rail','calldata-slots','evm-op-flow']) assert.match(js,new RegExp(token));
  assert.match(css,/\.calldata-slots/);
  assert.match(css,/\.evm-op-flow/);
});

test('track catalog restores registered vehicle AI and Web3 tools without cross-domain leakage',()=>{
  const source=read('renderer/track_surface_catalog.js');
  const sandbox={
    DOMAINS:{vehicle:{tools:[]},ai:{tools:[]},web3:{tools:[]},lowalt:{tools:[]}},
    TOOL_META:{
      'can-analyze':{domain:'vehicle',title:'CAN',label:'candump'},
      'ai-source-scan':{domain:'ai',title:'AI Source',label:'source'},
      'evm-calldata':{domain:'web3',title:'Calldata',label:'hex'},
      'mavlink-hex':{domain:'lowalt',title:'MAVLink',label:'frame'}
    }
  };
  vm.runInNewContext(source,sandbox);
  assert.deepEqual(sandbox.DOMAINS.vehicle.tools.map(x=>x[0]),['can-analyze']);
  assert.deepEqual(sandbox.DOMAINS.ai.tools.map(x=>x[0]),['ai-source-scan']);
  assert.deepEqual(sandbox.DOMAINS.web3.tools.map(x=>x[0]),['evm-calldata']);
  assert.deepEqual(sandbox.DOMAINS.lowalt.tools,[]);
});

test('specialized track tools still reuse the existing offline run-tool payload contract',()=>{
  const js=read('renderer/track_surfaces.js');
  assert.match(js,/id="tool-input" class="track-hidden-input"/);
  assert.match(js,/data-action="run-tool"/);
  assert.match(js,/确定性离线分析/);
  assert.match(js,/function sync\(tool\)/);
});
