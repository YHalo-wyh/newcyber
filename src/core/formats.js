const MACHINE_NAMES = {
  0x014c: 'x86', 0x8664: 'x86-64', 0x01c0: 'ARM', 0xaa64: 'ARM64', 0x01c4: 'ARMv7'
};

function readUInt(buffer, offset, size, littleEndian) {
  if (offset < 0 || offset + size > buffer.length) return null;
  return littleEndian ? buffer.readUIntLE(offset, size) : buffer.readUIntBE(offset, size);
}

function parseExecutable(buffer, type) {
  if (type === 'ELF 可执行文件' && buffer.length >= 20) {
    const littleEndian = buffer[5] !== 2;
    const machine = readUInt(buffer, 18, 2, littleEndian);
    const machines = { 3: 'x86', 8: 'MIPS', 20: 'PowerPC', 40: 'ARM', 62: 'x86-64', 183: 'ARM64', 243: 'RISC-V' };
    return {
      format: 'ELF',
      architecture: machines[machine] || `machine-${machine}`,
      bits: buffer[4] === 2 ? 64 : 32,
      endian: littleEndian ? 'little' : 'big'
    };
  }
  if (type === 'PE/Windows 可执行文件' && buffer.length >= 64) {
    const peOffset = buffer.readUInt32LE(0x3c);
    if (peOffset + 24 > buffer.length || buffer.subarray(peOffset, peOffset + 4).toString('hex') !== '50450000') return { format: 'PE', note: 'PE 头不在预览范围内或已损坏' };
    const machine = buffer.readUInt16LE(peOffset + 4);
    const sections = buffer.readUInt16LE(peOffset + 6);
    const characteristics = buffer.readUInt16LE(peOffset + 22);
    return { format: 'PE', architecture: MACHINE_NAMES[machine] || `machine-0x${machine.toString(16)}`, sections, dll: Boolean(characteristics & 0x2000) };
  }
  return null;
}

function parseZipEntries(buffer) {
  const entries = [];
  let offset = 0;
  while (offset + 30 <= buffer.length && entries.length < 500) {
    const signature = buffer.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]), offset);
    if (signature < 0 || signature + 30 > buffer.length) break;
    const compressedSize = buffer.readUInt32LE(signature + 18);
    const fileNameLength = buffer.readUInt16LE(signature + 26);
    const extraLength = buffer.readUInt16LE(signature + 28);
    const nameStart = signature + 30;
    const nameEnd = nameStart + fileNameLength;
    if (nameEnd > buffer.length) break;
    const name = buffer.subarray(nameStart, nameEnd).toString('utf8');
    entries.push(name);
    const nextOffset = nameEnd + extraLength + compressedSize;
    offset = nextOffset > signature && nextOffset <= buffer.length ? nextOffset : nameEnd;
  }
  const suspiciousPaths = entries.filter((name) => /(?:^|[\\/])\.\.(?:[\\/]|$)|^[\\/]|^[A-Za-z]:/.test(name));
  return {
    entries: entries.slice(0, 100),
    entryCountInPreview: entries.length,
    suspiciousPaths,
    truncated: entries.length > 100
  };
}

function parseNpy(buffer) {
  if (buffer.length < 12 || buffer.subarray(0, 6).toString('hex') !== '934e554d5059') return null;
  const major = buffer[6];
  const headerLength = major <= 1 ? buffer.readUInt16LE(8) : buffer.readUInt32LE(8);
  const headerOffset = major <= 1 ? 10 : 12;
  const header = buffer.subarray(headerOffset, Math.min(headerOffset + headerLength, buffer.length)).toString('latin1').trim();
  return { format: 'NumPy', version: `${major}.${buffer[7]}`, header };
}

function parseSafetensors(buffer) {
  if (buffer.length < 9) return null;
  const headerLength = Number(buffer.readBigUInt64LE(0));
  if (!Number.isSafeInteger(headerLength) || headerLength < 2 || headerLength > 16 * 1024 * 1024 || 8 + headerLength > buffer.length) return null;
  try {
    const header = JSON.parse(buffer.subarray(8, 8 + headerLength).toString('utf8'));
    const tensors = Object.entries(header).filter(([key]) => key !== '__metadata__').map(([name, value]) => ({ name, dtype: value.dtype, shape: value.shape }));
    return { format: 'SafeTensors', tensorCount: tensors.length, tensors: tensors.slice(0, 100), metadata: header.__metadata__ || null };
  } catch {
    return null;
  }
}

function findWavChunks(buffer) {
  if (buffer.length < 12 || buffer.subarray(0, 4).toString() !== 'RIFF' || buffer.subarray(8, 12).toString() !== 'WAVE') return null;
  let offset = 12;
  const chunks = {};
  while (offset + 8 <= buffer.length) {
    const id = buffer.subarray(offset, offset + 4).toString();
    const size = buffer.readUInt32LE(offset + 4);
    const start = offset + 8;
    chunks[id] = { start, size: Math.min(size, Math.max(buffer.length - start, 0)) };
    offset = start + size + (size % 2);
  }
  return chunks;
}

function goertzel(samples, sampleRate, frequency) {
  const normalized = frequency / sampleRate;
  const coefficient = 2 * Math.cos(2 * Math.PI * normalized);
  let previous = 0;
  let previous2 = 0;
  for (const sample of samples) {
    const current = sample + coefficient * previous - previous2;
    previous2 = previous;
    previous = current;
  }
  return previous2 * previous2 + previous * previous - coefficient * previous * previous2;
}

function parseWavSignal(buffer) {
  const chunks = findWavChunks(buffer);
  const formatChunk = chunks?.['fmt '];
  if (!formatChunk || !chunks?.data || formatChunk.size < 16) return null;
  const format = buffer.readUInt16LE(formatChunk.start);
  const channels = buffer.readUInt16LE(formatChunk.start + 2);
  const sampleRate = buffer.readUInt32LE(formatChunk.start + 4);
  const bitsPerSample = buffer.readUInt16LE(formatChunk.start + 14);
  const bytesPerSample = bitsPerSample / 8;
  const frameSize = channels * bytesPerSample;
  const sampleCount = frameSize ? Math.floor(chunks.data.size / frameSize) : 0;
  const durationSeconds = sampleRate ? sampleCount / sampleRate : 0;
  const result = { format: format === 1 ? 'PCM' : `WAV format ${format}`, channels, sampleRate, bitsPerSample, durationSeconds: Number(durationSeconds.toFixed(3)) };
  if (format !== 1 || bitsPerSample !== 16 || !sampleRate || !sampleCount) return result;

  const samples = new Float64Array(sampleCount);
  for (let index = 0; index < sampleCount; index += 1) {
    const position = chunks.data.start + index * frameSize;
    if (position + 2 > buffer.length) break;
    samples[index] = buffer.readInt16LE(position) / 32768;
  }
  const segmentSamples = Math.max(1, Math.round(sampleRate * 0.1));
  const segments = [];
  for (let start = 0; start < samples.length && segments.length < 200; start += segmentSamples) {
    const slice = samples.subarray(start, Math.min(start + segmentSamples, samples.length));
    if (slice.length < segmentSamples * 0.5) break;
    const energy600 = goertzel(slice, sampleRate, 600);
    let dominantFrequency = 0;
    let dominantEnergy = -1;
    for (let frequency = 100; frequency <= Math.min(3000, sampleRate / 2 - 1); frequency += 50) {
      const energy = goertzel(slice, sampleRate, frequency);
      if (energy > dominantEnergy) { dominantEnergy = energy; dominantFrequency = frequency; }
    }
    segments.push({ index: segments.length, energy600: Number(energy600.toExponential(3)), dominantFrequency });
  }
  if (segments.length) {
    const energies = segments.map((segment) => segment.energy600);
    const min = Math.min(...energies);
    const max = Math.max(...energies);
    const threshold = min + (max - min) * 0.5;
    const presenceBits = segments.map((segment) => segment.energy600 > threshold ? '1' : '0').join('');
    result.segmentSeconds = 0.1;
    result.frequency600PresenceBits = presenceBits;
    result.frequency600InverseBits = [...presenceBits].map((bit) => bit === '1' ? '0' : '1').join('');
    result.dominantFrequencies = segments.map((segment) => segment.dominantFrequency);
    result.frequency600Threshold = Number(threshold.toExponential(3));
  }
  return result;
}

function ipv4(buffer, offset) {
  if (offset + 4 > buffer.length) return null;
  return [...buffer.subarray(offset, offset + 4)].join('.');
}

function parsePcap(buffer) {
  if (buffer.length < 24) return null;
  const magic = buffer.subarray(0, 4).toString('hex');
  const littleEndian = magic === 'd4c3b2a1' || magic === '4d3cb2a1';
  if (!['d4c3b2a1', 'a1b2c3d4', '4d3cb2a1', 'a1b23c4d'].includes(magic)) return null;
  const read32 = (offset) => littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
  const read16 = (offset) => littleEndian ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
  const linkType = read32(20);
  let offset = 24;
  let packetCount = 0;
  const protocols = { tcp: 0, udp: 0, other: 0 };
  const flows = new Map();
  while (offset + 16 <= buffer.length && packetCount < 5000) {
    const capturedLength = read32(offset + 8);
    const packetStart = offset + 16;
    const packetEnd = packetStart + capturedLength;
    if (packetEnd > buffer.length) break;
    packetCount += 1;
    if (linkType === 1 && capturedLength >= 34 && buffer.readUInt16BE(packetStart + 12) === 0x0800) {
      const ipStart = packetStart + 14;
      const headerLength = (buffer[ipStart] & 0x0f) * 4;
      const protocol = buffer[ipStart + 9];
      const source = ipv4(buffer, ipStart + 12);
      const destination = ipv4(buffer, ipStart + 16);
      let flow = `${source} → ${destination}`;
      if ((protocol === 6 || protocol === 17) && ipStart + headerLength + 4 <= packetEnd) {
        const transportStart = ipStart + headerLength;
        const sourcePort = buffer.readUInt16BE(transportStart);
        const destinationPort = buffer.readUInt16BE(transportStart + 2);
        flow = `${source}:${sourcePort} → ${destination}:${destinationPort} ${protocol === 6 ? 'TCP' : 'UDP'}`;
        protocols[protocol === 6 ? 'tcp' : 'udp'] += 1;
      } else {
        protocols.other += 1;
      }
      flows.set(flow, (flows.get(flow) || 0) + 1);
    }
    offset = packetEnd;
  }
  return {
    format: 'PCAP',
    version: `${read16(4)}.${read16(6)}`,
    endian: littleEndian ? 'little' : 'big',
    linkType,
    packetCountInPreview: packetCount,
    protocols,
    topFlows: [...flows.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20).map(([flow, packets]) => ({ flow, packets }))
  };
}

function analyzeKnownFormat(buffer, type, extension) {
  if (type === 'WAV 音频') return parseWavSignal(buffer);
  if (type === 'PCAP 流量') return parsePcap(buffer);
  if (type === 'ELF 可执行文件' || type === 'PE/Windows 可执行文件') return parseExecutable(buffer, type);
  if (['Android APK', 'Java JAR', 'ZIP 压缩包'].includes(type) || ['.pt', '.pth'].includes(extension)) return { archive: parseZipEntries(buffer), safeModelInspection: ['.pt', '.pth'].includes(extension) };
  if (extension === '.npy') return parseNpy(buffer);
  if (extension === '.safetensors') return parseSafetensors(buffer);
  return null;
}

module.exports = { analyzeKnownFormat, parseExecutable, parseZipEntries, parseNpy, parseSafetensors, parseWavSignal, parsePcap, goertzel };
