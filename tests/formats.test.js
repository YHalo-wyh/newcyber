const test = require('node:test');
const assert = require('node:assert/strict');
const { parseWavSignal, parsePcap, parseExecutable, parseZipEntries } = require('../src/core/formats');

function wavWithToneBits(bits, sampleRate = 8000) {
  const segmentSamples = sampleRate / 10;
  const data = Buffer.alloc(bits.length * segmentSamples * 2);
  for (let segment = 0; segment < bits.length; segment += 1) {
    for (let index = 0; index < segmentSamples; index += 1) {
      const frequency = bits[segment] === '1' ? 600 : 1000;
      const value = Math.round(Math.sin(2 * Math.PI * frequency * index / sampleRate) * 20000);
      data.writeInt16LE(value, (segment * segmentSamples + index) * 2);
    }
  }
  const header = Buffer.alloc(44);
  header.write('RIFF', 0);
  header.writeUInt32LE(data.length + 36, 4);
  header.write('WAVEfmt ', 8);
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(1, 22);
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(sampleRate * 2, 28);
  header.writeUInt16LE(2, 32);
  header.writeUInt16LE(16, 34);
  header.write('data', 36);
  header.writeUInt32LE(data.length, 40);
  return Buffer.concat([header, data]);
}

test('从 0.1 秒分段 WAV 中恢复 600Hz 出现序列', () => {
  const result = parseWavSignal(wavWithToneBits('10110'));
  assert.equal(result.sampleRate, 8000);
  assert.equal(result.durationSeconds, 0.5);
  assert.equal(result.frequency600PresenceBits, '10110');
  assert.equal(result.frequency600InverseBits, '01001');
});

test('解析最小 PCAP 元数据', () => {
  const header = Buffer.alloc(24);
  Buffer.from('d4c3b2a1', 'hex').copy(header);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(1, 20);
  const result = parsePcap(header);
  assert.equal(result.version, '2.4');
  assert.equal(result.linkType, 1);
  assert.equal(result.packetCountInPreview, 0);
});

test('解析 ELF 架构', () => {
  const elf = Buffer.alloc(64);
  Buffer.from('7f454c46', 'hex').copy(elf);
  elf[4] = 2;
  elf[5] = 1;
  elf.writeUInt16LE(62, 18);
  assert.deepEqual(parseExecutable(elf, 'ELF 可执行文件'), { format: 'ELF', architecture: 'x86-64', bits: 64, endian: 'little' });
});

test('ZIP 列表标记路径穿越条目', () => {
  const name = Buffer.from('../escape.txt');
  const local = Buffer.alloc(30);
  Buffer.from('504b0304', 'hex').copy(local);
  local.writeUInt16LE(name.length, 26);
  const result = parseZipEntries(Buffer.concat([local, name]));
  assert.deepEqual(result.entries, ['../escape.txt']);
  assert.deepEqual(result.suspiciousPaths, ['../escape.txt']);
});
