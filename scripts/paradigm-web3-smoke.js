#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { auditSolidity } = require('../src/core/web3');

const sourcePath = process.argv[2];
if (!sourcePath) throw new Error('usage: node scripts/paradigm-web3-smoke.js <UNCX_ProofOfReservesV2_UniV3.sol>');
const source = fs.readFileSync(path.resolve(sourcePath), 'utf8');
const audit = auditSolidity(source);
const trust = audit.findings.filter((item) => item.id === 'external-contract-trust-boundary');
const nested = trust.find((item) => item.details?.dependencyExpression === 'params.nftPositionManager');
if (!nested) {
  throw new Error(`generic nested external-contract trust evidence not recovered: ${JSON.stringify(trust.slice(0, 8))}`);
}
if (nested.severity !== 'medium') {
  throw new Error(`unexpected trust severity: ${nested.severity}`);
}
for (const method of ['positions', 'factory']) {
  if (!nested.details?.methodCalls?.includes(method)) throw new Error(`missing ${method} dependency evidence`);
}
if (!audit.playbooks?.some((item) => item.id === 'web3.external-contract-trust')) {
  throw new Error('external-contract-trust playbook was not attached');
}
process.stdout.write(`${JSON.stringify({
  source: path.basename(sourcePath),
  finding: nested.id,
  dependency: nested.details.dependencyExpression,
  methods: nested.details.methodCalls,
  playbook: 'web3.external-contract-trust'
}, null, 2)}\n`);
