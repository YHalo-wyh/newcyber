const fs = require('fs');
const { analyzeEvmRuntime } = require('../src/core/evm_runtime');

const file = process.argv[2];
if (!file) throw new Error('usage: node scripts/lilctf-runtime-smoke.js <blockchain-treasure-README.md>');
const text = fs.readFileSync(file, 'utf8');
const candidates = [...text.matchAll(/```\s*\n(0x[0-9a-fA-F]{400,})\s*\n```/g)].map((match) => match[1]);
if (!candidates.length) throw new Error('LilCTF blockchain-treasure: runtime bytecode block not found');
const runtime = candidates.sort((a, b) => b.length - a.length)[0];
const result = analyzeEvmRuntime(runtime);

for (const selector of ['0x5cc4d812', '0x64d98f6e']) {
  if (!result.dispatcherSelectors.some((item) => item.selector === selector)) {
    throw new Error(`LilCTF blockchain-treasure: dispatcher selector missed: ${selector}`);
  }
}
const slot1 = result.storage.slots.find((item) => item.slot === '0x1');
if (!slot1 || slot1.reads < 1 || slot1.highConfidenceReads < 1) {
  throw new Error(`LilCTF blockchain-treasure: direct STORAGE[0x1] evidence missed: ${JSON.stringify(result.storage)}`);
}
if (result.storage.writes < 1) throw new Error('LilCTF blockchain-treasure: SSTORE evidence missed');

console.log('=== LilCTF 2025 blockchain-treasure ===');
console.log(JSON.stringify({
  byteLength: result.byteLength,
  selectors: result.dispatcherSelectors,
  storage: result.storage
}, null, 2));
console.log('LilCTF runtime corpus assertions passed.');
