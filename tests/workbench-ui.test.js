const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { buildMarkdownReport } = require('../src/core/workbench_analyzer');
const { auditPytorchAgainstTrainingLog } = require('../src/core/model');

function sampleAnalysis() {
  return {
    workspaceName: 'real-corpus',
    workspacePath: '/tmp/real-corpus',
    scannedAt: '2026-09-07T00:00:00.000Z',
    stats: { files: 2, bytes: 200000, findings: 1, flags: 0 },
    categories: [{ name: '取证 / 流量', score: 5 }, { name: 'AI / ML', score: 5 }],
    candidates: { flags: [] },
    recommendations: ['优先核对状态跃迁原始帧。'],
    findings: [{
      id: 'model-unexpected-parameter:model.pth',
      severity: 'high',
      title: '模型参数与训练日志不一致',
      file: 'model.pth',
      count: 1,
      evidence: '模型包含训练日志未声明的参数：feature_adapter.weight'
    }],
    files: [
      {
        name: 'light.pcapng', path: 'light.pcapng', type: 'PCAPNG 流量', extension: '.pcapng', size: 1697584,
        entropy: 3.2, flags: [], findings: [], sha256: 'a'.repeat(64), partialHash: false,
        metadata: { pcapng: { can: {
          parsedFrames: 35359, uniqueIds: 12,
          ids: [{ id: '0x188', count: 100, changingBytes: [0], counterCandidates: [], transitions: [{ frameIndex: 23418 }], averageIntervalMs: 10 }],
          eventCandidates: [{
            id: '0x188', frameIndex: 23418, packetIndex: 23418, payload: '02000000', rawFrameHex: '00000188040000000200000000000000',
            changes: [{ byteIndex: 0, from: 0, to: 2, setBits: 2, clearedBits: 0 }]
          }]
        } } }
      },
      {
        name: 'model.pth', path: 'model.pth', type: 'ZIP 压缩包', extension: '.pth', size: 194607,
        entropy: 7.9, flags: [], findings: [], sha256: 'b'.repeat(64), partialHash: false,
        metadata: {
          model: { storageCount: 9 },
          modelAudit: {
            unexpectedParameters: ['feature_adapter.weight'],
            suspiciousMappings: [{ parameter: 'feature_adapter.weight', storage: 'archive/data/8', storageBytes: 168880, mapping: 'pickle-order heuristic' }],
            storageOutliers: [{ name: 'archive/data/8', uncompressedSize: 168880, compressedSize: 168617 }],
            baselineBytes: 862208,
            exportedBytes: 1214464
          }
        }
      }
    ]
  };
}

test('导出报告保留 CAN 原始帧与模型异常证据', () => {
  const report = buildMarkdownReport(sampleAnalysis(), '人工复核中');
  assert.match(report, /深度解析证据/);
  assert.match(report, /00000188040000000200000000000000/);
  assert.match(report, /feature_adapter\.weight/);
  assert.match(report, /archive\/data\/8/);
  assert.match(report, /人工复核中/);
});

test('workspace evidence 扩展能把深度证据渲染到赛题页', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'workspace_evidence.js'), 'utf8');
  const context = {
    state: { workspace: sampleAnalysis() },
    workspaceView: () => '<section><div class="workspace-actions"></div></section>',
    esc: (value = '') => String(value).replace(/[&<>"']/g, ''),
    table: (headers, rows) => `<table data-headers="${headers.join('|')}">${rows.map((row) => `<tr>${row.join('|')}</tr>`).join('')}</table>`
  };
  vm.createContext(context);
  new vm.Script(source, { filename: 'workspace_evidence.js' }).runInContext(context);
  const html = context.workspaceView();
  assert.match(html, /关键线索/);
  assert.match(html, /CAN \/ PCAPNG 深度解析/);
  assert.match(html, /00000188040000000200000000000000/);
  assert.match(html, /feature_adapter\.weight/);
  assert.match(html, /archive\/data\/8/);
});

test('PyTorch 审计把未声明参数关联到对应 storage', () => {
  const inspection = {
    parameterNames: ['backbone.conv1.weight', 'classifier.fc.weight', 'feature_adapter.weight'],
    storageEntries: [
      { name: 'archive/data/0', uncompressedSize: 1728 },
      { name: 'archive/data/1', uncompressedSize: 5120 },
      { name: 'archive/data/2', uncompressedSize: 168880 }
    ],
    storageOutliers: [{ name: 'archive/data/2', uncompressedSize: 168880 }]
  };
  const log = '[2026-07-18] modules: backbone.conv1, classifier.fc\n';
  const audit = auditPytorchAgainstTrainingLog(inspection, log);
  assert.deepEqual(audit.unexpectedParameters, ['feature_adapter.weight']);
  assert.equal(audit.suspiciousMappings[0].storage, 'archive/data/2');
});
