const zlib = require('zlib');

const MAX_EXTRACTED_ENTRY = 16 * 1024 * 1024;

function findEocd(buffer) {
  const minimum = Math.max(0, buffer.length - 0x10000 - 22);
  for (let offset = buffer.length - 22; offset >= minimum; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) return offset;
  }
  return -1;
}

function parseZipCentralDirectory(buffer) {
  if (!buffer || buffer.length < 22) return null;
  const eocd = findEocd(buffer);
  if (eocd < 0) return null;
  const entryCount = buffer.readUInt16LE(eocd + 10);
  const directorySize = buffer.readUInt32LE(eocd + 12);
  const directoryOffset = buffer.readUInt32LE(eocd + 16);
  if (directoryOffset + directorySize > buffer.length) return null;

  const entries = [];
  let offset = directoryOffset;
  for (let index = 0; index < entryCount && index < 2000; index += 1) {
    if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== 0x02014b50) break;
    const flags = buffer.readUInt16LE(offset + 8);
    const compression = buffer.readUInt16LE(offset + 10);
    const crc32 = buffer.readUInt32LE(offset + 16);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const fileNameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const nameStart = offset + 46;
    const nameEnd = nameStart + fileNameLength;
    if (nameEnd > buffer.length) break;
    const name = buffer.subarray(nameStart, nameEnd).toString('utf8');
    entries.push({ name, flags, compression, crc32, compressedSize, uncompressedSize, localHeaderOffset });
    offset = nameEnd + extraLength + commentLength;
  }
  return { entries, entryCountDeclared: entryCount, directoryOffset, directorySize };
}

function extractZipEntry(buffer, entry) {
  const offset = entry.localHeaderOffset;
  if (offset + 30 > buffer.length || buffer.readUInt32LE(offset) !== 0x04034b50) return null;
  if (entry.uncompressedSize > MAX_EXTRACTED_ENTRY || entry.compressedSize > MAX_EXTRACTED_ENTRY) return null;
  const nameLength = buffer.readUInt16LE(offset + 26);
  const extraLength = buffer.readUInt16LE(offset + 28);
  const start = offset + 30 + nameLength + extraLength;
  const end = start + entry.compressedSize;
  if (end > buffer.length) return null;
  const data = buffer.subarray(start, end);
  if (entry.compression === 0) return Buffer.from(data);
  if (entry.compression === 8) {
    try {
      const inflated = zlib.inflateRawSync(data, { maxOutputLength: MAX_EXTRACTED_ENTRY });
      return inflated.length <= MAX_EXTRACTED_ENTRY ? inflated : null;
    } catch {
      return null;
    }
  }
  return null;
}

function printableStrings(buffer, minLength = 4) {
  if (!buffer?.length) return [];
  return [...new Set(buffer.toString('latin1').match(new RegExp(`[\\x20-\\x7e]{${minLength},}`, 'g')) || [])];
}

function extractParameterNames(pickleStrings) {
  const joined = (pickleStrings || []).join('\n');
  const matches = joined.match(/[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.(?:weight|bias|running_mean|running_var|num_batches_tracked)/g) || [];
  return [...new Set(matches)];
}

function shannonEntropy(buffer) {
  if (!buffer?.length) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte] += 1;
  let result = 0;
  for (const count of counts) {
    if (!count) continue;
    const p = count / buffer.length;
    result -= p * Math.log2(p);
  }
  return Number(result.toFixed(3));
}

function embeddedFormat(buffer) {
  if (!buffer?.length) return null;
  const hex = buffer.subarray(0, 16).toString('hex');
  if (hex.startsWith('89504e470d0a1a0a')) return 'PNG';
  if (hex.startsWith('ffd8ff')) return 'JPEG';
  if (hex.startsWith('504b0304')) return 'ZIP';
  if (hex.startsWith('25504446')) return 'PDF';
  if (hex.startsWith('7f454c46')) return 'ELF';
  if (hex.startsWith('4d5a')) return 'PE';
  if (hex.startsWith('52494646')) return 'RIFF';
  return null;
}

function scanStoragePayload(buffer, name) {
  if (!buffer) return null;
  const strings = printableStrings(buffer, 5).slice(0, 120);
  const joined = strings.join('\n');
  const flags = [...new Set(joined.match(/(?:flag|ctf|wqb|FLAG|CTF|WQB)\{[^}\r\n]{1,200}\}/g) || [])].slice(0, 20);
  const decodedCandidates = [];
  for (const value of strings) {
    if (value.length < 24 || value.length > 4096 || value.length % 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) continue;
    try {
      const decoded = Buffer.from(value, 'base64').toString('utf8');
      if (/^[\x09\x0a\x0d\x20-\x7e]{4,}$/.test(decoded)) decodedCandidates.push(decoded.slice(0, 500));
    } catch {}
  }
  const noteworthyStrings = strings.filter((value) => /flag|ctf|wqb|secret|token|hidden|payload|adapter/i.test(value)).slice(0, 30);
  return {
    name,
    bytes: buffer.length,
    entropy: shannonEntropy(buffer),
    embeddedFormat: embeddedFormat(buffer),
    flags,
    noteworthyStrings,
    decodedCandidates: [...new Set(decodedCandidates)].slice(0, 20)
  };
}

function inspectPytorchZip(buffer) {
  const zip = parseZipCentralDirectory(buffer);
  if (!zip) return null;
  const entries = zip.entries.map((entry) => ({
    name: entry.name,
    compression: entry.compression,
    compressedSize: entry.compressedSize,
    uncompressedSize: entry.uncompressedSize
  }));
  const dataPklEntry = zip.entries.find((entry) => /(^|\/)data\.pkl$/i.test(entry.name));
  const dataPkl = dataPklEntry ? extractZipEntry(buffer, dataPklEntry) : null;
  const pickleStrings = printableStrings(dataPkl, 3).slice(0, 500);
  const parameterNames = extractParameterNames(pickleStrings);
  const storageEntriesRaw = zip.entries
    .filter((entry) => /(^|\/)data\/\d+$/i.test(entry.name))
    .sort((a, b) => Number(a.name.match(/(\d+)$/)?.[1] || 0) - Number(b.name.match(/(\d+)$/)?.[1] || 0));
  const storageEntries = storageEntriesRaw.map((entry) => ({
    name: entry.name,
    compression: entry.compression,
    compressedSize: entry.compressedSize,
    uncompressedSize: entry.uncompressedSize
  }));
  const unusualNames = entries.filter((entry) => !/(^|\/)(data\.pkl|byteorder|version|\.data\/serialization_id|data\/\d+)$/i.test(entry.name));

  const storageSizes = storageEntries.map((entry) => entry.uncompressedSize).sort((a, b) => b - a);
  const storageOutliers = [];
  if (storageSizes.length >= 2 && storageSizes[0] > Math.max(storageSizes[1] * 4, 4096)) {
    storageOutliers.push(...storageEntries.filter((entry) => entry.uncompressedSize === storageSizes[0]));
  }

  const storageScans = storageEntriesRaw.map((entry) => scanStoragePayload(extractZipEntry(buffer, entry), entry.name)).filter(Boolean);
  const payloadEvidence = storageScans.filter((item) => item.flags.length || item.embeddedFormat || item.noteworthyStrings.length || item.decodedCandidates.length);

  return {
    format: 'PyTorch ZIP',
    entryCount: entries.length,
    entries,
    storageCount: storageEntries.length,
    storageEntries,
    storageOutliers,
    storageScans,
    payloadEvidence,
    parameterNames,
    pickleStrings,
    unusualNames,
    notes: [
      '仅解析 ZIP 中央目录、data.pkl 与 tensor storage 原始字节，不执行 pickle / torch.load。',
      'storage 数量、尺寸与训练日志/预期架构不一致时，应优先检查是否存在隐藏参数、适配器或附加数据。'
    ]
  };
}

function auditPytorchAgainstTrainingLog(inspection, trainingLog = '') {
  if (!inspection) return null;
  const text = String(trainingLog || '');
  const modulesMatch = text.match(/^\s*\[[^\]]+\]\s*modules:\s*(.+)$/mi) || text.match(/^\s*modules:\s*(.+)$/mi);
  const expectedModules = modulesMatch
    ? modulesMatch[1].split(',').map((item) => item.trim()).filter(Boolean)
    : [];
  const parameterNames = inspection.parameterNames || extractParameterNames(inspection.pickleStrings || []);
  const parameterModule = (name) => name.replace(/\.(?:weight|bias|running_mean|running_var|num_batches_tracked)$/, '');
  const isExpected = (name) => {
    const module = parameterModule(name);
    return expectedModules.some((expected) => module === expected || module.startsWith(`${expected}.`));
  };
  const unexpectedParameters = expectedModules.length ? parameterNames.filter((name) => !isExpected(name)) : [];

  const parameterStorageMap = [];
  if (parameterNames.length && parameterNames.length === inspection.storageEntries.length) {
    for (let index = 0; index < parameterNames.length; index += 1) {
      parameterStorageMap.push({
        parameter: parameterNames[index],
        storage: inspection.storageEntries[index].name,
        storageBytes: inspection.storageEntries[index].uncompressedSize,
        mapping: 'pickle-order heuristic'
      });
    }
  }
  const suspiciousMappings = parameterStorageMap.filter((item) => unexpectedParameters.includes(item.parameter));

  const baselineMatch = text.match(/baseline checkpoint size:\s*([0-9.]+)\s*(KB|MB|GB)/i);
  const exportedMatch = text.match(/exported checkpoint size:\s*([0-9.]+)\s*(KB|MB|GB)/i);
  const toBytes = (match) => {
    if (!match) return null;
    const multiplier = { KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3 }[match[2].toUpperCase()] || 1;
    return Math.round(Number(match[1]) * multiplier);
  };
  const baselineBytes = toBytes(baselineMatch);
  const exportedBytes = toBytes(exportedMatch);

  const findings = [];
  if (unexpectedParameters.length) findings.push({
    severity: 'high',
    type: 'unexpected-parameter',
    message: `模型包含训练日志未声明的参数：${unexpectedParameters.join(', ')}`,
    evidence: unexpectedParameters
  });
  if (inspection.storageOutliers?.length) findings.push({
    severity: 'medium',
    type: 'storage-size-outlier',
    message: `发现异常大的 tensor storage：${inspection.storageOutliers.map((item) => `${item.name} (${item.uncompressedSize} bytes)`).join(', ')}`,
    evidence: inspection.storageOutliers
  });
  if (inspection.payloadEvidence?.length) findings.push({
    severity: 'high',
    type: 'storage-payload-evidence',
    message: `tensor storage 中发现可疑载荷证据：${inspection.payloadEvidence.map((item) => item.name).join(', ')}`,
    evidence: inspection.payloadEvidence
  });
  if (baselineBytes && exportedBytes && exportedBytes > baselineBytes) findings.push({
    severity: 'medium',
    type: 'checkpoint-size-growth',
    message: `训练日志显示导出 checkpoint 比 baseline 大 ${exportedBytes - baselineBytes} bytes。`,
    evidence: { baselineBytes, exportedBytes, deltaBytes: exportedBytes - baselineBytes }
  });

  return {
    expectedModules,
    parameterNames,
    unexpectedParameters,
    parameterStorageMap,
    suspiciousMappings,
    storageOutliers: inspection.storageOutliers || [],
    payloadEvidence: inspection.payloadEvidence || [],
    baselineBytes,
    exportedBytes,
    findings
  };
}

module.exports = {
  parseZipCentralDirectory,
  extractZipEntry,
  inspectPytorchZip,
  printableStrings,
  extractParameterNames,
  scanStoragePayload,
  shannonEntropy,
  auditPytorchAgainstTrainingLog
};
