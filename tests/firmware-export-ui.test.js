const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { createBinaryArtifact } = require('../src/core/artifacts');
const { exportVerifiedFirmwareArtifacts } = require('../src/core/firmware_export');

const root = path.join(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

test('firmware recovery export writes verified files and SHA-256 manifest', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'newcyber-fw-export-'));
  try {
    const artifact = createBinaryArtifact({
      name: 'rootfs.squashfs',
      buffer: Buffer.from('hsqs-test-rootfs'),
      provenance: [{ source: 'squashfs-superblock', offset: 4096, length: 16 }],
      metadata: { kind: 'squashfs' }
    });
    const result = await exportVerifiedFirmwareArtifacts({ artifacts: [artifact], parentDir: dir, sourceName: 'router.bin' });
    assert.match(path.basename(result.outputDir), /^router-recovered/);
    assert.equal(result.files.length, 1);
    const saved = await fsp.readFile(path.join(result.outputDir, result.files[0].name));
    assert.equal(saved.toString(), 'hsqs-test-rootfs');
    const manifest = JSON.parse(await fsp.readFile(result.manifestPath, 'utf8'));
    assert.equal(manifest.source, 'router.bin');
    assert.equal(manifest.count, 1);
    assert.equal(manifest.files[0].sha256, artifact.sha256);
    assert.deepEqual(manifest.files[0].provenance, artifact.provenance);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('firmware recovery export rejects tampered artifact before writing output files', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'newcyber-fw-export-bad-'));
  try {
    const artifact = createBinaryArtifact({ name: 'kernel.bin', buffer: Buffer.from('kernel-data') });
    artifact.hex = Buffer.from('changed-data').toString('hex');
    await assert.rejects(
      exportVerifiedFirmwareArtifacts({ artifacts: [artifact], parentDir: dir, sourceName: 'fw.bin' }),
      /size 与 hex 不一致|SHA-256 校验失败/
    );
    assert.deepEqual(await fsp.readdir(dir), []);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('compact workbench UI loads last and firmware view exposes both export paths', () => {
  const html = read('renderer/toolbox.html');
  const ui = read('renderer/tool_ui.js');
  const css = read('renderer/styles/tool_ui.css');
  const firmware = read('renderer/uav_challenge_tools.js');
  const main = read('main.js');
  const preload = read('preload.js');
  assert.doesNotThrow(() => new vm.Script(ui, { filename: 'renderer/tool_ui.js' }));
  assert.ok(html.indexOf('tool_ui.js') > html.indexOf('investigation_panel.js'));
  assert.match(html, /styles\/tool_ui\.css/);
  assert.match(ui, /tool-home-head tool-home-head-minimal"><h1>NewCyber<\/h1>/);
  assert.doesNotMatch(ui, /LOCAL SECURITY WORKBENCH|一台机器解决重复劳动|面向线下断网决赛准备/);
  assert.match(css, /\.tool-home-head/);
  assert.match(firmware, /导出恢复结果/);
  assert.match(firmware, /Binwalk 解包到目录/);
  assert.match(main, /firmware:export-recovered/);
  assert.match(preload, /exportFirmwareRecovered/);
});
