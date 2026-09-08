function readTarString(buffer, start, length) {
  return buffer.subarray(start, start + length).toString('utf8').replace(/\0.*$/s, '').trim();
}

function readTarNumber(buffer, start, length) {
  const field = buffer.subarray(start, start + length);
  if (!field.length) return 0;
  if (field[0] & 0x80) {
    let value = BigInt(field[0] & 0x7f);
    for (let i = 1; i < field.length; i += 1) value = (value << 8n) | BigInt(field[i]);
    return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
  }
  const text = field.toString('ascii').replace(/\0/g, '').trim();
  if (!text) return 0;
  if (!/^[0-7]+$/.test(text)) return null;
  const value = parseInt(text, 8);
  return Number.isSafeInteger(value) ? value : null;
}

function checksumOk(header) {
  if (!header || header.length !== 512) return false;
  const expected = readTarNumber(header, 148, 8);
  if (!Number.isFinite(expected)) return false;
  let sum = 0;
  for (let i = 0; i < 512; i += 1) sum += (i >= 148 && i < 156) ? 0x20 : header[i];
  return sum === expected;
}

function isZeroBlock(block) {
  for (const byte of block) if (byte !== 0) return false;
  return true;
}

function isTar(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 1024) return false;
  const header = buffer.subarray(0, 512);
  const magic = readTarString(header, 257, 6);
  return (magic === 'ustar' || magic === 'ustar  ' || checksumOk(header)) && checksumOk(header);
}

function parseTar(buffer, options = {}) {
  if (!isTar(buffer)) return null;
  const maxEntries = Math.max(1, Math.min(Number(options.maxEntries) || 256, 4096));
  const maxEntryBytes = Math.max(1, Math.min(Number(options.maxEntryBytes) || 32 * 1024 * 1024, 128 * 1024 * 1024));
  const entries = [];
  let offset = 0;
  let zeroBlocks = 0;
  let longName = null;
  let truncated = false;
  while (offset + 512 <= buffer.length && entries.length < maxEntries) {
    const header = buffer.subarray(offset, offset + 512);
    if (isZeroBlock(header)) {
      zeroBlocks += 1;
      offset += 512;
      if (zeroBlocks >= 2) break;
      continue;
    }
    zeroBlocks = 0;
    if (!checksumOk(header)) { truncated = true; break; }
    const name = readTarString(header, 0, 100);
    const prefix = readTarString(header, 345, 155);
    const size = readTarNumber(header, 124, 12);
    const typeFlag = String.fromCharCode(header[156] || 0);
    if (!Number.isFinite(size) || size < 0) { truncated = true; break; }
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    const paddedEnd = dataStart + Math.ceil(size / 512) * 512;
    if (dataEnd > buffer.length || paddedEnd > buffer.length) { truncated = true; break; }
    const headerName = [prefix, name].filter(Boolean).join('/');
    if (typeFlag === 'L') {
      longName = buffer.subarray(dataStart, dataEnd).toString('utf8').replace(/\0.*$/s, '').trim().slice(0, 1024) || null;
    } else {
      entries.push({
        name: longName || headerName || `entry-${entries.length + 1}`,
        size,
        typeFlag:typeFlag || '0',
        mode:readTarString(header, 100, 8),
        mtime:readTarNumber(header, 136, 12),
        dataStart,
        dataEnd,
        regular:typeFlag === '0' || typeFlag === '\0' || header[156] === 0,
        exportable:size > 0 && size <= maxEntryBytes && (typeFlag === '0' || header[156] === 0)
      });
      longName = null;
    }
    offset = paddedEnd;
  }
  return { format:'TAR', entries, truncated, consumedBytes:offset };
}

function extractTarEntry(buffer, entry, maxBytes = 32 * 1024 * 1024) {
  if (!entry?.exportable || !Number.isFinite(entry.dataStart) || !Number.isFinite(entry.dataEnd)) return null;
  const size = entry.dataEnd - entry.dataStart;
  if (size <= 0 || size > maxBytes || entry.dataStart < 0 || entry.dataEnd > buffer.length) return null;
  return Buffer.from(buffer.subarray(entry.dataStart, entry.dataEnd));
}

function compressionKind(buffer) {
  if (!Buffer.isBuffer(buffer)) return null;
  if (buffer.length >= 6 && buffer.subarray(0, 6).equals(Buffer.from('fd377a585a00', 'hex'))) return 'XZ';
  if (buffer.length >= 4 && buffer.subarray(0, 3).toString('ascii') === 'BZh' && buffer[3] >= 0x31 && buffer[3] <= 0x39) return 'BZIP2';
  if (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) return 'GZIP';
  if (isTar(buffer)) return 'TAR';
  return null;
}

module.exports = { readTarNumber, checksumOk, isTar, parseTar, extractTarEntry, compressionKind };