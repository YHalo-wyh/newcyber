const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { scanWorkspace, detectType, entropy, extractSignals, buildMarkdownReport } = require('../src/core/analyzer');

test('识别常见文件签名', () => {
  assert.equal(detectType(Buffer.from('7f454c460201', 'hex'), ''), 'ELF 可执行文件');
  assert.equal(detectType(Buffer.from('4d5a9000', 'hex'), '.exe'), 'PE/Windows 可执行文件');
  assert.equal(detectType(Buffer.from('504b0304', 'hex'), '.apk'), 'Android APK');
  assert.equal(detectType(Buffer.from('0a0d0d0a', 'hex'), '.pcapng'), 'PCAPNG 流量');
});

test('熵值对确定性数据稳定', () => {
  assert.equal(entropy(Buffer.alloc(256, 0)), 0);
  assert.equal(entropy(Buffer.from([...Array(256).keys()])), 8);
});

test('提取候选结果和代码风险线索', () => {
  const source = `target = "flag{demo-value}"\nurl = "https://example.test/api"\ncmd = f"python task.py '{input}'"\nos.system(cmd)`;
  const result = extractSignals(source, 'app.py');
  assert.deepEqual(result.flags, ['flag{demo-value}']);
  assert.deepEqual(result.urls, ['https://example.test/api']);
  assert.equal(result.findings.some((item) => item.title === '可能存在命令拼接'), true);
});

test('扫描目录、分类并生成报告', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'newcyber-test-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, 'model.py'), 'import torch\nmodel = torch.load("sample.pth")\nprint("flag{verified}")');
  await fs.writeFile(path.join(root, 'sample.pth'), Buffer.from('504b0304', 'hex'));
  const result = await scanWorkspace(root);
  assert.equal(result.stats.files, 2);
  assert.equal(result.candidates.flags[0].value, 'flag{verified}');
  assert.equal(result.categories[0].name, 'AI / ML');
  assert.match(buildMarkdownReport(result, '已确认：测试记录'), /已确认：测试记录/);
});
