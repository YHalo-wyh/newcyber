'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

const root=path.join(__dirname,'..');

test('Batch32 UAV Scenario Intelligence renderer compiles and exposes role ROS2 mission evidence',()=>{
  const js=fs.readFileSync(path.join(root,'renderer/uav_scenario_intel_batch32.js'),'utf8');
  const css=fs.readFileSync(path.join(root,'renderer/styles/uav_scenario_intel.css'),'utf8');
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  assert.doesNotThrow(()=>new Function(js));
  assert.match(js,/REFERENCE BASIS/);
  assert.match(js,/ROLE MAP/);
  assert.match(js,/ROS 2 \/ DDS GRAPH/);
  assert.match(js,/MISSION TRANSFER/);
  assert.match(js,/MISSION_COUNT-1/);
  assert.match(css,/uav32-role-grid/);
  assert.match(css,/uav32-session-list/);
  assert.match(html,/styles\/uav_scenario_intel\.css/);
  assert.match(html,/uav_scenario_intel_batch32\.js/);
  assert.ok(html.indexOf('uav_batch8_tools.js') < html.indexOf('uav_scenario_intel_batch32.js'));
});
