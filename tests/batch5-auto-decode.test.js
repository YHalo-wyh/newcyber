const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { scanWorkspace, extractSuspiciousStrings } = require('../src/core/finals_analyzer_batch5');

const root = path.join(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

test('workspace suspicious-string extractor finds encoded candidates conservatively', () => {
  const source = 'normal text\nblob=666c61677b746573747d\nother=SGVsbG8gd29ybGQ=';
  const items = extractSuspiciousStrings(source);
  assert.ok(items.some((item) => item.kind === 'hex' && item.value.includes('666c6167')));
  assert.ok(items.some((item) => item.kind === 'base64' && item.value.includes('SGVsbG8')));
});

test('workspace auto decode promotes a decoded flag into normal flag candidates', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'newcyber-auto-decode-'));
  try {
    const flag = 'flag{workspace_decode}';
    const hex = Buffer.from(flag, 'utf8').toString('hex');
    const encoded = Buffer.from(hex, 'utf8').toString('base64');
    await fsp.writeFile(path.join(dir, 'clue.txt'), `payload=${encoded}\n`, 'utf8');
    const analysis = await scanWorkspace(dir);
    const clue = analysis.files.find((file) => file.path === 'clue.txt');
    assert.ok(clue);
    assert.ok(clue.flags.includes(flag));
    assert.ok(clue.metadata?.autoDecode?.candidates?.some((item) => item.foundFlag === flag));
    assert.ok(analysis.findings.some((item) => item.title === '自动解码命中 Flag 候选'));
    assert.ok(analysis.stats.flags >= 1);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('auto decode renderer extension stays compilable and loads after competition mode', () => {
  const source = read('renderer/auto_decode_tools.js');
  assert.doesNotThrow(() => new vm.Script(source, { filename: 'renderer/auto_decode_tools.js' }));
  const html = read('renderer/toolbox.html');
  assert.ok(html.indexOf('auto_decode_tools.js') > html.indexOf('competition_mode.js'));
});

test('auto decode UI keeps results simple and actionable', () => {
  const source = read('renderer/auto_decode_tools.js');
  assert.match(source, /拿到一段可疑数据？自动试解/);
  assert.match(source, /发现 Flag 候选/);
  assert.match(source, /下一步/);
  assert.match(source, /data-auto-decode-artifact/);
});

test('Electron workspace keeps batch-five capability through a later analyzer wrapper', () => {
  const main = read('main.js');
  assert.match(main, /finals_analyzer_batch(?:5|6)/);
});
