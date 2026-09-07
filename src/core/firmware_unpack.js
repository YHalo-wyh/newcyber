const zlib = require('zlib');
const { createBinaryArtifact } = require('./artifacts');

const MAX_FIRMWARE_BYTES = 512 * 1024 * 1024;

function u32be(buffer, offset) { return offset + 4 <= buffer.length ? buffer.readUInt32BE(offset) : null; }
function u32le(buffer, offset) { return offset + 4 <= buffer.length ? buffer.readUInt32LE(offset) : null; }
function u64leNumber(buffer, offset) {
  if (offset + 8 > buffer.length) return null;
  const value = buffer.readBigUInt64LE(offset);
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
}
function printable(buffer) { return buffer.toString('latin1').replace(/[^\x20-\x7e]/g, '.'); }

function entropy(buffer) {
  if (!buffer.length) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte] += 1;
  let out = 0;
  for (const count of counts) if (count) { const p = count / buffer.length; out -= p * Math.log2(p); }
  return Number(out.toFixed(4));
}

function scanMagic(buffer) {
  const signatures = [
    { id:'elf', name:'ELF', bytes:Buffer.from('7f454c46','hex') },
    { id:'uimage', name:'U-Boot uImage', bytes:Buffer.from('27051956','hex') },
    { id:'squashfs-le', name:'SquashFS', bytes:Buffer.from('68737173','hex') },
    { id:'squashfs-be', name:'SquashFS(BE)', bytes:Buffer.from('73717368','hex') },
    { id:'ubi', name:'UBI EC header', bytes:Buffer.from('55424923','hex') },
    { id:'jffs2-le', name:'JFFS2', bytes:Buffer.from('8519','hex') },
    { id:'cramfs-le', name:'CramFS', bytes:Buffer.from('453dcd28','hex') },
    { id:'gzip', name:'gzip', bytes:Buffer.from('1f8b08','hex') },
    { id:'xz', name:'XZ', bytes:Buffer.from('fd377a585a00','hex') },
    { id:'zip', name:'ZIP', bytes:Buffer.from('504b0304','hex') },
    { id:'png', name:'PNG', bytes:Buffer.from('89504e470d0a1a0a','hex') },
    { id:'dtb', name:'Device Tree Blob', bytes:Buffer.from('d00dfeed','hex') }
  ];
  const hits = [];
  for (const sig of signatures) {
    let start = 0;
    let count = 0;
    while (start < buffer.length && count < 128) {
      const offset = buffer.indexOf(sig.bytes, start);
      if (offset < 0) break;
      hits.push({ id:sig.id, name:sig.name, offset, offsetHex:`0x${offset.toString(16)}` });
      start = offset + 1; count += 1;
    }
  }
  return hits.sort((a,b)=>a.offset-b.offset);
}

function saneSegment(buffer, name, offset, length, source) {
  if (!Number.isInteger(offset) || !Number.isInteger(length) || offset < 0 || length <= 0) return null;
  if (offset + length > buffer.length) return { name, offset, length, complete:false, source, error:'declared-range-outside-file' };
  const data = buffer.subarray(offset, offset + length);
  return {
    name, offset, offsetHex:`0x${offset.toString(16)}`, length, endOffset:offset+length, complete:true, source,
    entropy: entropy(data),
    magic: scanMagic(data.subarray(0, Math.min(data.length, 256))).map((x)=>({ ...x, offset:x.offset+offset, offsetHex:`0x${(x.offset+offset).toString(16)}` })),
    artifact:createBinaryArtifact({ name:`firmware-${name}.bin`, mediaType:'application/octet-stream', buffer:data, completeness:'complete', provenance:[{ source:'firmware-segment', offset, length, parser:source }], metadata:{ kind:'firmware-segment', segment:name, offset, source } })
  };
}

function parseTpLink(buffer) {
  if (buffer.length < 0xa0) return null;
  const head = printable(buffer.subarray(0, 0x80));
  let version = null;
  if (/ver\. 1\.0/i.test(head)) version = '1.0';
  else if (/ver\. 2\.0/i.test(head)) version = '2.0';
  else if (/fw-type:Cloud/i.test(head)) version = 'cloud';
  if (!version) return null;
  const layout = version === '1.0'
    ? { kernelOffset:0x80, kernelLength:0x84, rootfsOffset:0x88, rootfsLength:0x8c, bootOffset:0x90, bootLength:0x94, total:0x7c }
    : version === '2.0'
      ? { kernelOffset:0x74, kernelLength:0x78, rootfsOffset:0x7c, rootfsLength:0x80, bootOffset:0x84, bootLength:0x88, total:0x70 }
      : null;
  if (!layout) return { vendor:'TP-Link', version, headerPreview:head, segments:[], notes:['Cloud 格式已识别；当前不假设其私有字段布局。'] };
  const fields = {};
  for (const [key, off] of Object.entries(layout)) fields[key] = u32be(buffer, off);
  const segments = [
    saneSegment(buffer,'kernel',fields.kernelOffset,fields.kernelLength,`tplink-v${version}`),
    saneSegment(buffer,'rootfs',fields.rootfsOffset,fields.rootfsLength,`tplink-v${version}`),
    saneSegment(buffer,'bootloader',fields.bootOffset,fields.bootLength,`tplink-v${version}`)
  ].filter(Boolean);
  return { vendor:'TP-Link', version, headerPreview:head, fields, segments, notes:['只有偏移与长度同时落在文件范围内才生成可导出的 segment artifact。'] };
}

function parseUImage(buffer, offset) {
  if (offset + 64 > buffer.length || u32be(buffer, offset) !== 0x27051956) return null;
  const dataSize = u32be(buffer, offset + 12);
  const total = 64 + dataSize;
  const complete = offset + total <= buffer.length;
  return {
    type:'uImage', offset, offsetHex:`0x${offset.toString(16)}`, headerSize:64, dataSize, totalSize:total, complete,
    loadAddress:u32be(buffer,offset+16), entryPoint:u32be(buffer,offset+20), os:buffer[offset+28], arch:buffer[offset+29], imageType:buffer[offset+30], compression:buffer[offset+31],
    name:buffer.subarray(offset+32,offset+64).toString('latin1').replace(/\0.*$/,'').trim(),
    artifact:complete ? createBinaryArtifact({ name:'uimage.bin', mediaType:'application/octet-stream', buffer:buffer.subarray(offset,offset+total), completeness:'complete', provenance:[{source:'uimage-header',offset,length:total}], metadata:{kind:'firmware-uimage',offset,dataSize} }) : null
  };
}

function parseSquashFs(buffer, offset) {
  if (offset + 96 > buffer.length || buffer.subarray(offset,offset+4).toString('hex') !== '68737173') return null;
  const bytesUsed = u64leNumber(buffer, offset + 40);
  const blockSize = u32le(buffer, offset + 12);
  const inodes = u32le(buffer, offset + 4);
  const complete = Number.isInteger(bytesUsed) && bytesUsed > 0 && offset + bytesUsed <= buffer.length;
  return {
    type:'squashfs', offset, offsetHex:`0x${offset.toString(16)}`, bytesUsed, blockSize, inodes, complete,
    artifact:complete ? createBinaryArtifact({ name:'rootfs.squashfs', mediaType:'application/octet-stream', buffer:buffer.subarray(offset,offset+bytesUsed), completeness:'complete', provenance:[{source:'squashfs-superblock',offset,length:bytesUsed}], metadata:{kind:'squashfs',offset,bytesUsed,blockSize,inodes} }) : null,
    extractor:'unsquashfs'
  };
}

function tryGunzip(buffer, offset) {
  try {
    const out = zlib.gunzipSync(buffer.subarray(offset), { finishFlush:zlib.constants.Z_SYNC_FLUSH });
    if (!out.length) return null;
    return {
      type:'gzip-stream', offset, offsetHex:`0x${offset.toString(16)}`, outputSize:out.length, complete:true,
      artifact:createBinaryArtifact({ name:'gzip-decoded.bin', mediaType:'application/octet-stream', buffer:out, completeness:'complete', provenance:[{source:'gzip',offset}], metadata:{kind:'gzip-decoded',offset} })
    };
  } catch { return null; }
}

function analyzeFirmwareBuffer(input, options = {}) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input || []);
  if (!buffer.length) throw new Error('固件数据为空');
  if (buffer.length > MAX_FIRMWARE_BYTES) throw new Error(`固件分析上限 ${MAX_FIRMWARE_BYTES} bytes`);
  const magic = scanMagic(buffer);
  const tplink = parseTpLink(buffer);
  const structures = [];
  for (const hit of magic) {
    if (hit.id === 'uimage') { const item = parseUImage(buffer, hit.offset); if (item) structures.push(item); }
    if (hit.id === 'squashfs-le') { const item = parseSquashFs(buffer, hit.offset); if (item) structures.push(item); }
    if (hit.id === 'gzip' && options.tryDecompress !== false) { const item = tryGunzip(buffer, hit.offset); if (item) structures.push(item); }
  }
  if (tplink?.segments?.length) structures.push(...tplink.segments);
  const uniqueArtifacts = [];
  const seen = new Set();
  for (const item of structures) {
    if (!item.artifact) continue;
    if (seen.has(item.artifact.sha256)) continue;
    seen.add(item.artifact.sha256); uniqueArtifacts.push(item.artifact);
  }
  const highEntropy = entropy(buffer.subarray(0, Math.min(buffer.length, 1024*1024))) >= 7.5;
  const knownFs = magic.some((x)=>['squashfs-le','squashfs-be','jffs2-le','ubi','cramfs-le'].includes(x.id));
  const findings = [];
  if (tplink) findings.push({ severity:'info', id:'firmware-vendor-header', title:`识别 TP-Link 固件头 ${tplink.version}`, evidence:tplink.headerPreview.slice(0,96) });
  if (knownFs) findings.push({ severity:'info', id:'firmware-filesystem', title:'发现嵌入式文件系统候选', evidence:magic.filter((x)=>['squashfs-le','squashfs-be','jffs2-le','ubi','cramfs-le'].includes(x.id)).map((x)=>`${x.name}@${x.offsetHex}`).join(', ') });
  if (!knownFs && highEntropy) findings.push({ severity:'medium', id:'firmware-high-entropy-container', title:'固件主体高熵且未识别常见 rootfs', evidence:'可能是压缩、加密或厂商私有封装；先寻找头部长度/校验/密钥派生代码。' });
  const backends = [
    { tool:'binwalk', purpose:'签名扫描/递归提取', args:['-eM','<firmware>'], preferred:true },
    { tool:'unsquashfs', purpose:'SquashFS 解包', args:['-d','<output>','<squashfs>'], when:'squashfs' },
    { tool:'jefferson', purpose:'JFFS2 解包', args:['-d','<output>','<jffs2>'], when:'jffs2' },
    { tool:'ubireader_extract_files', purpose:'UBI/UBIFS 解包', args:['-o','<output>','<ubi>'], when:'ubi' }
  ];
  return {
    size:buffer.length,
    entropy:entropy(buffer.subarray(0,Math.min(buffer.length,1024*1024))),
    headerHex:buffer.subarray(0,Math.min(buffer.length,64)).toString('hex'),
    headerAscii:printable(buffer.subarray(0,Math.min(buffer.length,96))),
    vendor:tplink,
    magic,
    structures,
    artifacts:uniqueArtifacts,
    findings,
    backends,
    nextActions:[
      uniqueArtifacts.some((x)=>x.metadata?.kind==='squashfs') ? '已恢复完整 SquashFS：优先解包 rootfs 后审计 etc/init.d、Web/API、SSH/Telnet、密钥、更新校验与默认配置。' : null,
      magic.some((x)=>x.id==='ubi') ? '检测到 UBI：使用 ubi reader 恢复 volume，再识别 UBIFS/rootfs。' : null,
      magic.some((x)=>x.id==='jffs2-le') ? '检测到 JFFS2：按 erase block/endianness 验证后提取文件树。' : null,
      !knownFs && highEntropy ? '未识别常见文件系统且高熵：优先寻找厂商头、解密脚本、升级程序中的 key/KDF/校验逻辑。' : null
    ].filter(Boolean)
  };
}

module.exports = { MAX_FIRMWARE_BYTES, entropy, scanMagic, parseTpLink, parseUImage, parseSquashFs, analyzeFirmwareBuffer };
