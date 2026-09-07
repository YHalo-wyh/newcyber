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
    stats: { files: 4, bytes: 420000, findings: 3, flags: 0 },
    categories: [{ name: '取证 / 流量', score: 5 }, { name: 'AI / ML', score: 5 }, { name: '低空经济', score: 9 }, { name: '区块链', score: 7 }],
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
      },
      {
        name: 'eeprom.bin', path: 'eeprom.bin', type: '二进制数据', extension: '.bin', size: 16384,
        entropy: 1.2, flags: [], findings: [], sha256: 'c'.repeat(64), partialHash: false,
        metadata: {
          lowAltitude: {
            format: 'ArduPilot AP_Param EEPROM', header: 'PA', headerHex: '50410600',
            signing: {
              offset: 8064, offsetHex: '0x1f80', magic: '0x3852fcd1', magicValid: true,
              timestamp: '123456789', keyLength: 32,
              signingKeyHex: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
              signingKeySha256: 'd'.repeat(64)
            }
          }
        }
      },
      {
        name: 'SelfAuthorizedVault.sol', path: 'SelfAuthorizedVault.sol', type: '文本/源码', extension: '.sol', size: 4096,
        entropy: 4.5, flags: [], findings: [], sha256: 'e'.repeat(64), partialHash: false,
        metadata: {
          web3Audit: {
            summary: { high: 1, medium: 1, low: 0 },
            findings: [
              { severity: 'high', line: 24, id: 'abi-smuggling-offset', title: '动态 bytes 授权使用硬编码 calldata 偏移', message: '授权 selector 与实际 actionData selector 可能不一致。' },
              { severity: 'medium', line: 7, id: 'first-caller-init', title: '公开的一次性初始化入口', message: '确认首次调用者权限。' }
            ]
          }
        }
      }
    ]
  };
}

test('导出报告保留 CAN、模型、UAV 和 Web3 深度证据', () => {
  const report = buildMarkdownReport(sampleAnalysis(), '人工复核中');
  assert.match(report, /深度解析证据/);
  assert.match(report, /00000188040000000200000000000000/);
  assert.match(report, /feature_adapter\.weight/);
  assert.match(report, /archive\/data\/8/);
  assert.match(report, /ArduPilot \/ MAVLink/);
  assert.match(report, /0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20/);
  assert.match(report, /Solidity 静态审计/);
  assert.match(report, /abi-smuggling-offset/);
  assert.match(report, /人工复核中/);
});

test('workspace evidence 扩展能把四赛道深度证据渲染到赛题页', () => {
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
  assert.match(html, /ArduPilot \/ MAVLink 深度解析/);
  assert.match(html, /0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20/);
  assert.match(html, /Solidity 静态审计/);
  assert.match(html, /abi-smuggling-offset/);
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
