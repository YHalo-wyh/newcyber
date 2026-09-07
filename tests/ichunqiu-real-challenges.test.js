const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeCanAdvanced } = require('../src/core/vehicle');
const { auditAiChallengeSource } = require('../src/core/ai_source');

// Regression source: 2022 数字中国创新大赛车联网安全赛 / 春秋GAME公开解析《雾里看CAN》.
// The public writeup gives these SDO payloads verbatim. Standard node-1 SDO COB-IDs
// (0x601/0x581) are used here so the regression verifies protocol semantics rather than
// depending on a capture-specific node number.
test('i春秋车联网真题：CANopen segmented upload 重组 0x1008 设备名', () => {
  const capture = [
    '601#4008100000000000',
    '581#4108100015000000',
    '601#6000000000000000',
    '581#0043414e6f70656e',
    '601#7000000000000000',
    '581#1044656d6f4c696e',
    '601#6000000000000000',
    '581#0175782d39663162'
  ].join('\n');

  const result = analyzeCanAdvanced(capture);
  assert.equal(result.canopen.detected, true);
  const transfer = result.canopen.transfers.find((item) => item.index === '0x1008' && item.direction === 'upload');
  assert.ok(transfer);
  assert.equal(transfer.complete, true);
  assert.equal(transfer.totalLength, 21);
  assert.equal(transfer.objectName, 'Manufacturer Device Name');
  assert.equal(transfer.value.ascii, 'CANopenDemoLinux-9f1b');
});

test('i春秋车联网真题：CANopen 0x1000 expedited upload 提取设备类型', () => {
  const capture = [
    '601#4000100000000000',
    '581#4300100034316637'
  ].join('\n');
  const result = analyzeCanAdvanced(capture);
  const value = result.canopen.objectValues.find((item) => item.index === '0x1000');
  assert.ok(value);
  assert.equal(value.objectName, 'Device Type');
  assert.equal(value.value.ascii, '41f7');
});

// Regression source: 2025 湾区杯公开题解中的 AI/ASR command-injection chain.
// Keep names generic enough to guard the reusable data-flow rule instead of one challenge.
test('AI 真题链：transcription 拼入 create_subprocess_shell 命中高危', () => {
  const source = `
import asyncio
import whisper

model = whisper.load_model('base')
result = model.transcribe('/tmp/input.wav')
transcription = result['text']
cmd = f"printf '%s' {transcription}"
proc = await asyncio.create_subprocess_shell(cmd)
`;
  const audit = auditAiChallengeSource(source);
  const finding = audit.findings.find((item) => item.id === 'ai-output-shell-injection');
  assert.ok(finding);
  assert.equal(finding.severity, 'high');
});

test('AI 安全负例：ASR 文本作为 argv 参数不应触发 shell 注入链', () => {
  const source = `
import asyncio
transcription = recognized_text
proc = await asyncio.create_subprocess_exec('printf', '%s', transcription)
`;
  const audit = auditAiChallengeSource(source);
  assert.equal(audit.findings.some((item) => item.id === 'ai-output-shell-injection'), false);
});
