const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const { searchKnowledge, knowledgeStats } = require('../src/knowledge');
const { runTool } = require('../src/core/tool_router');
const { auditSolidity } = require('../src/core/web3');
const { auditAiChallengeSource } = require('../src/core/ai_source');
const { decodeUdsAdvanced } = require('../src/core/vehicle_final');
const { analyzeMavlinkAdvanced } = require('../src/core/low_altitude_final');
const { decryptCryptoContext } = require('../src/core/context_crypto');
const { generateSuite } = require('../scripts/generate-generalization-corpus');

const root = path.join(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

function findingIds(result) {
  return new Set((result.findings || []).map((item) => item.id));
}

test('structured knowledge base covers all current tracks with verification-oriented playbooks', () => {
  const stats = knowledgeStats();
  assert.ok(stats.total >= 38);
  assert.ok(stats.tracks.common >= 6);
  assert.ok(stats.tracks.vehicle >= 7);
  assert.ok(stats.tracks.lowalt >= 7);
  assert.ok(stats.tracks.ai >= 8);
  assert.ok(stats.tracks.web3 >= 10);

  const uds = searchKnowledge('SecurityAccess seed key', '车联网');
  assert.ok(uds.some((item) => item.id === 'vehicle.uds-session-security'));
  const oracle = searchKnowledge('oracle flashloan price', '区块链');
  assert.ok(oracle.some((item) => item.id === 'web3.oracle-price'));

  const routed = runTool('knowledge-search', { input: 'delegatecall storage', domain: '区块链' });
  assert.ok(routed.results.some((item) => item.id === 'web3.delegatecall-storage'));
  const first = routed.results[0];
  assert.ok(Array.isArray(first.verify));
  assert.ok(Array.isArray(first.actions));
  assert.ok(Array.isArray(first.falsePositives));
  assert.ok(Array.isArray(first.mutations));
});

test('general Web3 audit detects caller-controlled direct and nested contract dependencies', () => {
  const source = `
pragma solidity ^0.8.20;
interface IFeed { function quote(uint256) external view returns (uint256); }
struct Request { IFeed feed; uint256 amount; }
contract Target {
  function direct(IFeed feed, uint256 amount) external view returns (uint256) {
    return feed.quote(amount);
  }
  function nested(Request calldata req) external view returns (uint256) {
    return req.feed.quote(req.amount);
  }
}
`;
  const audit = auditSolidity(source);
  const trust = audit.findings.filter((item) => item.id === 'external-contract-trust-boundary');
  assert.ok(trust.some((item) => item.details?.dependencyExpression === 'feed' && item.severity === 'medium'));
  assert.ok(trust.some((item) => item.details?.dependencyExpression === 'req.feed' && item.severity === 'medium'));
  assert.ok(audit.playbooks.some((item) => item.id === 'web3.external-contract-trust'));
});

test('Web3 trust rule lowers confidence when source constrains dependency and packed-dynamic rule has a clean negative', () => {
  const source = `
pragma solidity ^0.8.20;
interface IFeed { function quote(uint256) external view returns (uint256); }
contract Target {
  IFeed immutable TRUSTED_FEED;
  constructor(IFeed feed) { TRUSTED_FEED = feed; }
  function quote(IFeed feed, uint256 amount) external view returns (uint256) {
    require(feed == TRUSTED_FEED, "trusted");
    return feed.quote(amount);
  }
  function hashPair(string calldata a, bytes calldata b) external pure returns (bytes32) {
    return keccak256(abi.encode(a, b));
  }
}
`;
  const audit = auditSolidity(source);
  const trust = audit.findings.find((item) => item.id === 'external-contract-trust-boundary');
  assert.ok(trust);
  assert.equal(trust.severity, 'low');
  assert.equal(audit.findings.some((item) => item.id === 'abi-packed-dynamic-collision'), false);
});

test('generalization corpus is deterministic and contains balanced semantic variants', () => {
  const a = generateSuite({ seed: 'ci-generalization-v1', count: 4 });
  const b = generateSuite({ seed: 'ci-generalization-v1', count: 4 });
  assert.deepEqual(a, b);
  assert.equal(a.cases.length, 20);
  for (const track of ['web3', 'ai', 'vehicle', 'lowalt', 'common']) {
    const cases = a.cases.filter((item) => item.track === track);
    assert.equal(cases.length, 4);
    assert.ok(cases.some((item) => item.positive));
    assert.ok(cases.some((item) => !item.positive));
  }
});

test('generated Web3 variants survive identifier changes and reject trusted/abi.encode negatives', () => {
  const cases = generateSuite({ seed: 'web3-holdout-v1', count: 6 }).cases.filter((item) => item.track === 'web3');
  for (const item of cases) {
    const audit = auditSolidity(item.input);
    const ids = findingIds(audit);
    if (item.positive) {
      for (const id of item.expected.findingIds) assert.ok(ids.has(id), `${item.id}: missing ${id}`);
    } else {
      for (const id of item.expected.absentFindingIds || []) assert.equal(ids.has(id), false, `${item.id}: unexpected ${id}`);
      const trust = audit.findings.find((finding) => finding.id === 'external-contract-trust-boundary');
      assert.ok(!trust || trust.severity === 'low', `${item.id}: trusted dependency escalated to ${trust?.severity}`);
    }
  }
});

test('generated AI variants preserve output-to-shell semantics without flagging argv-safe negatives', () => {
  const cases = generateSuite({ seed: 'ai-holdout-v1', count: 6 }).cases.filter((item) => item.track === 'ai');
  for (const item of cases) {
    const ids = findingIds(auditAiChallengeSource(item.input));
    if (item.positive) assert.ok(ids.has('ai-output-shell-injection'), `${item.id}: shell flow missed`);
    else assert.equal(ids.has('ai-output-shell-injection'), false, `${item.id}: safe argv flow flagged`);
  }
});

test('generated vehicle variants decode SecurityAccess independent of CAN ID', () => {
  const cases = generateSuite({ seed: 'vehicle-holdout-v1', count: 6 }).cases.filter((item) => item.track === 'vehicle');
  for (const item of cases) {
    const lines = item.input.split(/\r?\n/);
    const request = decodeUdsAdvanced(lines[0]);
    const seed = decodeUdsAdvanced(lines[1]);
    const key = decodeUdsAdvanced(lines[2]);
    const outcome = decodeUdsAdvanced(lines[3]);
    assert.equal(request.securityAccess?.meaning, 'requestSeed', `${item.id}: requestSeed missed`);
    assert.equal(seed.securityAccess?.seedOrKey, `0x${item.expected.seedHex}`, `${item.id}: seed missed`);
    assert.equal(key.securityAccess?.meaning, 'sendKey', `${item.id}: sendKey missed`);
    if (item.positive) assert.equal(outcome.securityAccess?.meaning, 'sendKey', `${item.id}: positive response missed`);
    else assert.equal(outcome.nrcName, 'invalidKey', `${item.id}: invalidKey NRC missed`);
  }
});

test('generated MAVLink variants validate CRC while sysid/compid/sequence change', () => {
  const cases = generateSuite({ seed: 'mavlink-holdout-v1', count: 6 }).cases.filter((item) => item.track === 'lowalt');
  for (const item of cases) {
    const result = analyzeMavlinkAdvanced(item.input);
    assert.equal(result.frames.length, 1, `${item.id}: frame parse failed`);
    assert.equal(result.frames[0].sysid, item.expected.sysid);
    assert.equal(result.frames[0].compid, item.expected.compid);
    assert.equal(result.frames[0].crc?.status, item.expected.crcStatus, `${item.id}: crc status mismatch`);
  }
});

test('generated crypto variants recover complete contexts and refuse missing-IV negatives', () => {
  const cases = generateSuite({ seed: 'crypto-holdout-v1', count: 6 }).cases.filter((item) => item.track === 'common');
  for (const item of cases) {
    const result = decryptCryptoContext(item.input);
    if (item.positive) {
      assert.equal(result.foundFlag, item.expected.flag, `${item.id}: flag not recovered`);
      assert.ok(result.tried > 0);
    } else {
      assert.equal(result.tried, 0, `${item.id}: analyzer guessed missing IV`);
      assert.ok(result.context.missing.includes(item.expected.missing));
    }
  }
});

test('knowledge renderer compiles and professional wording is loaded last', () => {
  const source = read('renderer/knowledge_tools.js');
  assert.doesNotThrow(() => new vm.Script(source, { filename: 'renderer/knowledge_tools.js' }));
  assert.match(source, /赛题知识库/);
  assert.match(source, /验证路径与比赛动作/);
  assert.match(source, /Deterministic analysis pipeline/);
  const html = read('renderer/toolbox.html');
  assert.ok(html.indexOf('knowledge_tools.js') > html.indexOf('context_crypto_workspace.js'));
});
