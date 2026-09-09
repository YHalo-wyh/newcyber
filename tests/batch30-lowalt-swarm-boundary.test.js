const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

const {analyzeSwarmCoordination}=require('../src/core/lowalt_swarm');
const {analyzeCrossBoundaryFlow}=require('../src/core/lowalt_cross_boundary');
const {buildLowaltAssessment}=require('../src/core/lowalt_assessment_mode');
const {runTool}=require('../src/core/tool_router');

const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

test('Batch30 swarm workbench finds role, replay, task-conflict and clock evidence without confirming a vuln',()=>{
  const sample=[
    'type=LEADER src=uav-01 role=leader term=7 seq=40 auth=signed addr=10.0.0.11 session=K1',
    'type=TASK_ASSIGN src=uav-01 dst=uav-02 role=leader task=T-88 seq=41 auth=signed route=R-A',
    'type=TASK_ASSIGN src=uav-02 dst=uav-03 role=follower task=T-88 seq=8 auth=none route=R-B',
    'type=TASK_ASSIGN src=uav-02 dst=uav-03 role=follower task=T-88 seq=8 auth=none route=R-B',
    'type=TIME_SYNC src=uav-03 offset_ms=5300'
  ].join('\n');
  const result=analyzeSwarmCoordination(sample);
  assert.equal(result.schema,'newcyber.lowalt-swarm.v1');
  assert.equal(result.summary.members,3);
  assert.equal(result.summary.leaders,1);
  assert.equal(result.summary.tasks,1);
  const ids=new Set(result.findings.map((x)=>x.id));
  assert.ok(ids.has('swarm-follower-control'));
  assert.ok(ids.has('swarm-replay-candidate'));
  assert.ok(ids.has('swarm-task-conflict'));
  assert.ok(ids.has('swarm-time-skew'));
  assert.ok(result.findings.every((x)=>x.state==='candidate'));
});

test('Batch30 swarm analyzer keeps keyword-only text as evidence, not a fabricated conflict',()=>{
  const result=analyzeSwarmCoordination('swarm leader broadcast task assignment formation peer');
  assert.equal(result.summary.candidates,0);
  assert.ok(result.findings.length===0);
});

test('Batch30 detects two active leaders in the same term as a candidate only',()=>{
  const result=analyzeSwarmCoordination([
    'type=LEADER src=uav-A role=leader term=9 state=active-leader auth=signed',
    'type=LEADER src=uav-B role=leader term=9 state=active-leader auth=signed'
  ].join('\n'));
  const finding=result.findings.find((x)=>x.id==='swarm-multiple-leaders');
  assert.ok(finding);
  assert.deepEqual(new Set(finding.leaders),new Set(['uav-A','uav-B']));
  assert.equal(finding.state,'candidate');
});

test('Batch30 links APP GCS FC PHYSICAL only through a shared correlation and exposes the impact skeleton',()=>{
  const sample=[
    'stage=APP trace=TX-42 order=ORD-137 action=PATCH auth=idor status=200 actor=merchant-7',
    'stage=GCS trace=TX-42 task=TASK-9 mission=M-77 action=dispatch status=accepted actor=dispatcher',
    'stage=FC trace=TX-42 mission=M-77 msg=MISSION_ITEM_INT auth=unsigned status=accepted sysid=1',
    'stage=PHYSICAL trace=TX-42 mission=M-77 event=flight_log state=mission_changed vehicle=uav-01'
  ].join('\n');
  const result=analyzeCrossBoundaryFlow(sample);
  assert.equal(result.schema,'newcyber.lowalt-cross-boundary.v1');
  assert.equal(result.summary.observedStages,4);
  assert.equal(result.summary.bestCoverage,'4/4');
  const best=result.paths.find((p)=>p.correlation==='trace:TX-42');
  assert.ok(best);
  assert.deepEqual(best.stages,['APP','GCS','FC','PHYSICAL']);
  const ids=new Set(result.findings.filter((x)=>x.correlation==='trace:TX-42').map((x)=>x.id));
  assert.ok(ids.has('cross-boundary-auth-flow'));
  assert.ok(ids.has('business-to-physical-impact'));
  assert.ok(result.findings.every((x)=>x.state==='candidate'));
});

test('Batch30 refuses to draw an attack path when four layers exist without a common trace/task/mission/order',()=>{
  const result=analyzeCrossBoundaryFlow([
    'stage=APP order=ORD-1 action=PATCH auth=idor status=200',
    'stage=GCS task=TASK-2 action=dispatch status=accepted',
    'stage=FC mission=M-3 msg=MISSION_ITEM_INT status=accepted',
    'stage=PHYSICAL route=R-4 event=flight_log state=mission_changed'
  ].join('\n'));
  assert.equal(result.summary.observedStages,4);
  assert.equal(result.summary.linkedPaths,0);
  assert.equal(result.summary.bestCoverage,'0/4');
  assert.ok(result.gaps.some((x)=>/没有共享|不连边|关联标识/.test(x)));
  assert.equal(result.findings.length,0);
});

test('Batch29 assessment absorbs Batch30 candidates but never lets them close verification',()=>{
  const sample=[
    'type=TASK_ASSIGN src=uav-02 dst=uav-03 role=follower task=T-88 seq=8 auth=none route=R-B',
    'stage=APP trace=TX-42 order=ORD-137 auth=idor status=200',
    'stage=GCS trace=TX-42 task=TASK-9 status=accepted',
    'stage=FC trace=TX-42 mission=M-77 msg=MISSION_ITEM_INT auth=unsigned status=accepted',
    'stage=PHYSICAL trace=TX-42 mission=M-77 event=flight_log state=mission_changed'
  ].join('\n');
  const result=buildLowaltAssessment(sample);
  assert.ok(result.extensions.swarm);
  assert.ok(result.extensions.crossBoundary);
  assert.ok(result.findings.some((x)=>x.source==='swarm-coordination'));
  assert.ok(result.findings.some((x)=>x.source==='cross-boundary-flow'));
  assert.ok(result.findings.filter((x)=>x.source!=='analyst-observation').every((x)=>x.closureTracked===false));
  assert.notEqual(result.gates.find((g)=>g.id==='verify').status,'complete');
});

test('tool router exposes both Batch30 analyzers',()=>{
  const swarm=runTool('lowalt-swarm-coordination',{input:{text:'type=LEADER src=a role=leader term=1'}});
  const flow=runTool('lowalt-cross-boundary-flow',{input:{text:'stage=APP trace=T1 order=O1\nstage=GCS trace=T1 task=K1'}});
  assert.equal(swarm.schema,'newcyber.lowalt-swarm.v1');
  assert.equal(flow.schema,'newcyber.lowalt-cross-boundary.v1');
  assert.ok(flow.summary.linkedPaths>=1);
});

test('Batch30 UI is two dedicated workbenches and loads immediately after Batch29 assessment UI',()=>{
  const js=read('renderer/lowalt_batch30_tools.js');
  const css=read('renderer/styles/lowalt_batch30.css');
  const html=read('renderer/toolbox.html');
  assert.doesNotThrow(()=>new Function(js));
  assert.match(js,/EVENT TAPE/);
  assert.match(js,/MEMBER REGISTRY/);
  assert.match(js,/COORDINATION GRAPH/);
  assert.match(js,/APP → GCS → FC/);
  assert.match(js,/STRICT CORRELATION/);
  assert.match(js,/UNLINKED EVIDENCE/);
  assert.doesNotMatch(js,/id=\"tool-input\"/);
  assert.match(css,/b30-stage-rail/);
  assert.match(css,/b30-swarm-board/);
  assert.match(html,/styles\/lowalt_batch30\.css/);
  assert.match(html,/lowalt_batch30_tools\.js/);
  assert.ok(html.indexOf('lowalt_batch30_tools.js')>html.indexOf('lowalt_assessment_tools.js'));
});
