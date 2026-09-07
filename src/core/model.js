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
  const pickleStrings = printableStrings(dataPkl, 3).slice(0, 300);
  const storageEntries = entries
    .filter((entry) => /(^|\/)data\/\d+$/i.test(entry.name))
    .sort((a, b) => Number(a.name.match(/(\d+)$/)?.[1] || 0) - Number(b.name.match(/(\d+)$/)?.[1] || 0));
  const unusualNames = entries.filter((entry) => !/(^|\/)(data\.pkl|byteorder|version|\.data\/serialization_id|data\/\d+)$/i.test(entry.name));

  return {
    format: 'PyTorch ZIP',
    entryCount: entries.length,
    entries,
    storageCount: storageEntries.length,
    storageEntries,
    pickleStrings,
    unusualNames,
    notes: [
      '仅解析 ZIP 中央目录并读取 data.pkl 字节，不执行 pickle / torch.load。',
      'storage 数量、尺寸与训练日志/预期架构不一致时，应优先检查是否存在隐藏参数、适配器或附加数据。'
    ]
  };
}

module.exports = { parseZipCentralDirectory, extractZipEntry, inspectPytorchZip, printableStrings };
