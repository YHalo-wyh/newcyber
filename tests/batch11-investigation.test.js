const test = require('node:test');
const assert = require('node:assert/strict');
const { buildInvestigationGraph, inferTool, inferExploitability } = require('../src/core/investigation_graph');

function baseAnalysis(findings = [], files = []) {
  return { findings, files, stats:{ files:files.length, bytes:0, findings:findings.length, flags:0 }, recommendations:[] };
}

test('investigation graph maps AI supply-chain findings to a concrete verifier tool and preserves fix/regression', () => {
  const finding = {
    id:'hf-trust-remote-code:server.py:7', originalId:'hf-trust-remote-code', severity:'high', title:'Hugging Face 允许远端自定义代码', file:'server.py', line:7,
    evidence:'trust_remote_code=True', meaning:'远端仓库自定义代码可进入执行边界。',
    fix:{ action:'固定 revision 并移除 trust_remote_code=True', regression:'恶意 revision 不得被加载' }
  };
  const graph = buildInvestigationGraph(baseAnalysis([finding],[{path:'server.py',type:'text',metadata:{}}]));
  assert.equal(graph.focus[0].recommendedTool, 'ai-supply-chain');
  assert.equal(graph.focus[0].fix, finding.fix.action);
  assert.equal(graph.focus[0].regression, finding.fix.regression);
  assert.match(graph.focus[0].prerequisite, /攻击者|题目输入边界|artifact|模型|RAG/i);
  assert.ok(graph.nextActions.some((item)=>item.tool==='ai-supply-chain'));
});

test('confirmed MAVLink state evidence is prioritized and routed to MAVLink analysis', () => {
  const finding = { id:'fence-param-confirmed', severity:'high', title:'地理围栏参数变更已回读确认', file:'flight.log', evidence:'PARAM_SET FENCE_ENABLE=0 -> PARAM_VALUE=0 change confirmed' };
  assert.equal(inferTool(finding,'lowalt'),'mavlink-hex');
  assert.equal(inferExploitability(finding),'confirmed');
  const graph=buildInvestigationGraph(baseAnalysis([finding],[{path:'flight.log',metadata:{}}]));
  assert.equal(graph.summary.confirmed,1);
  assert.equal(graph.focus[0].track,'lowalt');
  assert.match(graph.focus[0].nextAction,/source|MAVLink|控制链/i);
});

test('graph exposes complete artifacts by reference without embedding binary hex', () => {
  const artifact={ name:'ecu.bin', size:4, sha256:'a'.repeat(64), completeness:'complete', hex:'41424344', metadata:{} };
  const analysis=baseAnalysis([], [{ path:'capture.pcapng', metadata:{ pcapng:{ can:{ udsProgramming:{ transfers:[{ artifact }] } } } } }]);
  const graph=buildInvestigationGraph(analysis);
  assert.equal(graph.summary.artifacts,1);
  assert.equal(graph.artifacts[0].source,'uds');
  assert.equal(graph.artifacts[0].name,'ecu.bin');
  assert.equal(Object.prototype.hasOwnProperty.call(graph.artifacts[0],'hex'),false);
  assert.ok(graph.nextActions.some((item)=>item.artifactId===graph.artifacts[0].id));
});

test('low-confidence evidence stays candidate rather than being upgraded to confirmed', () => {
  const finding={ id:'external-contract-trust-boundary', severity:'medium', title:'Caller-controlled external contract trust', file:'Vault.sol', evidence:'adapter.quote() influences accounting' };
  const graph=buildInvestigationGraph(baseAnalysis([finding],[{path:'Vault.sol',metadata:{}}]));
  assert.notEqual(graph.focus[0].exploitability,'confirmed');
  assert.equal(graph.focus[0].track,'web3');
  assert.equal(graph.focus[0].recommendedTool,'evm-disasm');
});
