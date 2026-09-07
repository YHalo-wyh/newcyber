const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

test('competition mode renderer stays compilable', () => {
  assert.doesNotThrow(() => new vm.Script(read('renderer/competition_mode.js'), { filename: 'renderer/competition_mode.js' }));
});

test('competition mode loads after advanced renderer extensions', () => {
  const html = read('renderer/toolbox.html');
  const batch4 = html.indexOf('batch4_tools.js');
  const competition = html.indexOf('competition_mode.js');
  assert.ok(batch4 >= 0);
  assert.ok(competition > batch4);
  assert.match(html, /styles\/competition_mode\.css/);
});

test('competition mode defaults to actionable beginner output and keeps advanced evidence folded', () => {
  const source = read('renderer/competition_mode.js');
  assert.match(source, /现在按这个顺序做/);
  assert.match(source, /最值得追的线索/);
  assert.match(source, /优先看的文件/);
  assert.match(source, /展开技术细节（卡住时再看）/);
  assert.match(source, /data-competition-artifact/);
  assert.match(source, /window\.newcyber\.saveArtifact\(artifact\)/);
  assert.doesNotMatch(source, /data-artifact-hex/);
});

test('competition mode still exposes all four tracks', () => {
  const source = read('renderer/competition_mode.js');
  for (const name of ['车联网安全', '低空经济安全', '人工智能安全', '区块链安全']) assert.match(source, new RegExp(name));
});

test('competition mode renders a real actionable workspace summary', () => {
  const context = {
    homeView: () => '<div>old home</div>',
    workspaceView: () => '<div>old workspace technical details</div>',
    state: {
      workspace: {
        workspaceName: 'demo',
        categories: [{ name: '车联网', score: 12 }],
        findings: [{ severity: 'high', title: '发现 UDS 刷写链', file: 'traffic.pcapng' }],
        files: [{
          path: 'traffic.pcapng',
          type: 'PCAPNG 流量',
          size: 4096,
          flags: ['flag{demo}'],
          findings: [{ severity: 'high', title: '发现 UDS 刷写链' }],
          metadata: {
            pcapng: {
              can: {
                udsProgramming: {
                  exportableTransfers: 1,
                  transfers: [{
                    artifactReady: true,
                    firmwareSize: 4,
                    artifact: {
                      name: 'uds-demo.firmware.bin',
                      size: 4,
                      metadata: { kind: 'uds-firmware-candidate', rawTransferPayload: false }
                    }
                  }]
                }
              }
            }
          }
        }]
      }
    },
    esc: (value) => String(value ?? ''),
    fmtBytes: (value) => `${value} B`,
    render: () => {},
    toast: () => {},
    document: { addEventListener: () => {} },
    window: { newcyber: { saveArtifact: async () => ({ filePath: 'x', size: 4, sha256: 'a'.repeat(64) }) } },
    console
  };
  vm.createContext(context);
  vm.runInContext(read('renderer/competition_mode.js'), context);
  const html = context.workspaceView();
  assert.match(html, /车联网安全/);
  assert.match(html, /flag\{demo\}/);
  assert.match(html, /ECU 固件候选/);
  assert.match(html, /直接导出/);
  assert.match(html, /发现 UDS 刷写链/);
  assert.match(html, /old workspace technical details/);
});
