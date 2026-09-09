const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { SOURCE_BASIS, SURFACES, CLOSURE_GATES, buildLowaltAssessment } = require('../src/core/lowalt_assessment_mode');
const { runTool } = require('../src/core/tool_router');

const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

test('Batch29 keeps official facts separate from Bay Area Cup preparation inference',()=>{
  const official=SOURCE_BASIS.filter((item)=>item.level==='official-fact');
  const inference=SOURCE_BASIS.filter((item)=>item.level==='prep-inference');
  assert.ok(official.length>=3);
  assert.equal(inference.length,1);
  assert.match(inference[0].supports.join(' '),/不代表|不.*复用|不得|并非/);
  assert.ok(official.some((item)=>item.supports.join(' ').includes('无人机蜂群协同')));
  assert.ok(official.some((item)=>item.supports.join(' ').includes('低空经济安全')));
});

test('Batch29 assessment is organized by four business scenes, not only attack categories',()=>{
  assert.deepEqual(SURFACES.map((surface)=>surface.id),['flight-control','swarm','ground-station','logistics-system']);
  assert.deepEqual(CLOSURE_GATES.map((gate)=>gate.id),['discover','verify','impact','remediate','retest']);
  const sample=[
    'ArduPilot MAVLink COMMAND_LONG and PARAM_SET observed on flight controller link',
    'swarm leader broadcast task assignment to formation peers',
    'ground station GCS Wi-Fi WPA2 RTSP telemetry endpoint',
    'logistics order REST API JWT authorization route dispatch'
  ].join('\n');
  const result=buildLowaltAssessment(sample);
  assert.equal(result.coverage.surfaces,4);
  assert.equal(result.coverage.observed,4);
  for (const surface of result.surfaces) assert.notEqual(surface.status,'unchecked',surface.id);
});

test('automatic evidence stays candidate and cannot close verification by itself',()=>{
  const result=buildLowaltAssessment('MAVLink unsigned COMMAND_LONG from a new GCS stream\nGPS position jump\nRTSP endpoint exposed');
  assert.ok(result.findings.every((finding)=>finding.state==='candidate'));
  const verify=result.gates.find((gate)=>gate.id==='verify');
  assert.notEqual(verify.status,'complete');
  assert.equal(result.coverage.validated,0);
});

test('validated manual finding still needs impact remediation and retest fields for full closure',()=>{
  const partial=buildLowaltAssessment({observations:[{
    surface:'flight-control', title:'unsigned high-risk control accepted', evidence:'COMMAND_LONG accepted from unauthorized stream', state:'validated'
  }]});
  assert.equal(partial.gates.find((gate)=>gate.id==='verify').status,'complete');
  assert.equal(partial.gates.find((gate)=>gate.id==='impact').status,'missing');
  assert.equal(partial.gates.find((gate)=>gate.id==='retest').status,'missing');

  const closed=buildLowaltAssessment({observations:[{
    surface:'flight-control', title:'unsigned high-risk control accepted', evidence:'COMMAND_LONG accepted from unauthorized stream',
    impact:'unauthorized operator can change flight state', remediation:'require signed control stream and source authorization',
    retest:'same unsigned frame is rejected after fix', state:'retested'
  }]});
  assert.ok(closed.gates.every((gate)=>gate.status==='complete'));
  assert.equal(closed.coverage.closureComplete,5);
});

test('tool router exposes assessment and provenance catalog',()=>{
  const result=runTool('lowalt-assessment-mode',{input:{text:'蜂群 leader broadcast task assignment'}});
  assert.equal(result.schema,'newcyber.lowalt-assessment.v1');
  assert.equal(result.surfaces.find((surface)=>surface.id==='swarm').status,'observed');
  const catalog=runTool('lowalt-assessment-catalog',{});
  assert.equal(catalog.schema,'newcyber.lowalt-assessment-catalog.v1');
  assert.equal(catalog.surfaces.length,4);
});

test('dedicated low-altitude UI is scenario-board based and loaded by toolbox',()=>{
  const js=read('renderer/lowalt_assessment_tools.js');
  const css=read('renderer/styles/lowalt_assessment.css');
  const html=read('renderer/toolbox.html');
  assert.doesNotThrow(()=>new Function(js));
  assert.match(js,/EVIDENCE INBOX/);
  assert.match(js,/ASSESSMENT BOARD/);
  assert.match(js,/OFFICIAL FACT/);
  assert.match(js,/PREP INFERENCE/);
  assert.match(js,/data-lowalt-surface/);
  assert.doesNotMatch(js,/id=\"tool-input\"/);
  assert.match(css,/lowalt-surface-rail/);
  assert.match(html,/styles\/lowalt_assessment\.css/);
  assert.match(html,/lowalt_assessment_tools\.js/);
  assert.ok(html.indexOf('lowalt_assessment_tools.js') > html.indexOf('track_surfaces.js'));
});

test('low-altitude knowledge entries require remediation and retest instead of challenge-only wording',()=>{
  const knowledge=require('../src/knowledge/lowalt_matrix');
  assert.ok(knowledge.length>20);
  assert.ok(knowledge.every((item)=>item.assessment?.automaticVerdict==='candidate-only'));
  assert.ok(knowledge.every((item)=>item.assessment?.workflow?.includes('retest')));
  assert.ok(knowledge.every((item)=>item.actions.some((action)=>/修复|复测/.test(action))));
});
