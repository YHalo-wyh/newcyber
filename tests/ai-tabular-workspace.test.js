const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { scanWorkspace, buildMarkdownReport } = require('../src/core/finals_analyzer');

test('workspace auto-detects public_ledger style high-dimensional AI data', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'newcyber-ai-tabular-'));
  try {
    const headers = ['amount', ...Array.from({ length: 10 }, (_, i) => `f${i + 1}`)];
    const rows = Array.from({ length: 12 }, (_, row) => [1000 + row * 50, ...Array.from({ length: 10 }, (_, col) => (row + 1) * (col + 2))]);
    const csv = [headers.join(','), ...rows.map((item) => item.join(','))].join('\n');
    await fs.writeFile(path.join(root, 'public_ledger.csv'), csv);

    const analysis = await scanWorkspace(root);
    const file = analysis.files.find((item) => item.path === 'public_ledger.csv');
    assert.ok(file?.metadata?.aiTabular);
    assert.ok(analysis.categories.some((item) => item.name === '人工智能'));
    assert.ok(analysis.recommendations.some((item) => /高维结构化 AI 数据/.test(item)));
    const report = buildMarkdownReport(analysis, 'tabular test');
    assert.match(report, /AI 结构化数据/);
    assert.match(report, /Strong correlations/);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('ordinary low-dimensional CSV is not force-classified as AI', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'newcyber-csv-'));
  try {
    await fs.writeFile(path.join(root, 'contacts.csv'), 'name,age,city\na,20,x\nb,21,y');
    const analysis = await scanWorkspace(root);
    const file = analysis.files.find((item) => item.path === 'contacts.csv');
    assert.ok(file);
    assert.equal(file.metadata?.aiTabular, undefined);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
