const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { decryptCryptoContext } = require('../src/core/context_crypto');
const { scanWorkspace, buildMarkdownReport } = require('../src/core/finals_analyzer_batch6');

const root = path.join(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

function assertAnalyzerAtLeast(main, minimum) {
  const match = main.match(/finals_analyzer_batch(\d+)/);
  assert.ok(match, 'main.js should load a finals analyzer wrapper');
  assert.ok(Number(match[1]) >= minimum, `expected analyzer batch >= ${minimum}, got ${match[1]}`);
}

const SOURCE = `
from Crypto.Cipher import AES
key = b"0123456789abcdef"
iv = b"abcdef9876543210"
ciphertext = bytes.fromhex("1c3283f1c199a78698919361e70f619c51c850d4f8328773f35fdc3540708b99")
cipher = AES.new(key, AES.MODE_CBC, iv)
`;

test('batch6 workspace promotes context-decrypted flag and report evidence', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'newcyber-crypto-'));
  try {
    await fsp.writeFile(path.join(dir, 'solve.py'), SOURCE);
    const analysis = await scanWorkspace(dir);
    const file = analysis.files.find((item) => item.path === 'solve.py');
    assert.ok(file?.metadata?.contextCrypto);
    assert.equal(file.metadata.contextCrypto.foundFlag, 'flag{context_crypto_ok}');
    assert.ok(file.flags.includes('flag{context_crypto_ok}'));
    assert.ok(analysis.findings.some((item) => item.id.startsWith('context-crypto-flag:')));
    const report = buildMarkdownReport(analysis);
    assert.match(report, /上下文强加密试解/);
    assert.match(report, /flag\{context_crypto_ok\}/);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('context crypto emits exportable artifact when AES plaintext has known file magic', () => {
  const source = `
from Crypto.Cipher import AES
key = b"0123456789abcdef"
iv = b"abcdef9876543210"
ciphertext = bytes.fromhex("0b72140149e70a793ca06828663b37753b41da0af339dd5e1b3b7d8d4746c38c")
cipher = AES.new(key, AES.MODE_CBC, iv)
`;
  const result = decryptCryptoContext(source);
  const candidate = result.bestCandidates.find((item) => item.magic === 'PNG');
  assert.ok(candidate);
  assert.ok(candidate.artifact);
  assert.equal(candidate.artifact.completeness, 'complete');
  assert.equal(candidate.artifact.metadata.kind, 'crypto-decrypted-candidate');
});

test('batch6 renderer extensions compile and load after auto decode', () => {
  assert.doesNotThrow(() => new vm.Script(read('renderer/context_crypto_tools.js'), { filename: 'renderer/context_crypto_tools.js' }));
  assert.doesNotThrow(() => new vm.Script(read('renderer/context_crypto_workspace.js'), { filename: 'renderer/context_crypto_workspace.js' }));
  const html = read('renderer/toolbox.html');
  const auto = html.indexOf('auto_decode_tools.js');
  const crypto = html.indexOf('context_crypto_tools.js');
  const workspace = html.indexOf('context_crypto_workspace.js');
  assert.ok(auto >= 0);
  assert.ok(crypto > auto);
  assert.ok(workspace > crypto);
});

test('Electron entrypoint compiles and keeps batch6 or later workspace wrapper', () => {
  const main = read('main.js');
  assert.doesNotThrow(() => new vm.Script(main, { filename: 'main.js' }));
  assertAnalyzerAtLeast(main,6);
});
