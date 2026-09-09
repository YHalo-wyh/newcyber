'use strict';

const MAX_ELF_BYTES = 96 * 1024 * 1024;
const MAX_SECTIONS = 4096;
const MAX_SYMBOLS = 200000;
const MAX_OBJECTS = 6000;
const MAX_RELATIONS = 12000;
const MAX_STRING_OBJECTS = 1600;
const MAX_PREVIEW_BYTES = 4096;
const MAX_SCAN_BYTES_PER_SECTION = 12 * 1024 * 1024;
const MAX_TOTAL_STRING_SCAN_BYTES = 24 * 1024 * 1024;

const SHT = Object.freeze({ NULL:0, PROGBITS:1, SYMTAB:2, STRTAB:3, RELA:4, NOBITS:8, REL:9, DYNSYM:11 });
const SHF = Object.freeze({ WRITE:1n, ALLOC:2n, EXECINSTR:4n });
const STT = Object.freeze({ NOTYPE:0, OBJECT:1, FUNC:2 });

const MACHINE_NAMES = Object.freeze({
  3:'x86', 8:'MIPS', 20:'PowerPC', 21:'PowerPC64', 40:'ARM', 62:'x86-64', 183:'AArch64', 243:'RISC-V'
});
const TYPE_NAMES = Object.freeze({ 0:'NONE', 1:'REL', 2:'EXEC', 3:'DYN', 4:'CORE' });
const SECTION_TYPE_NAMES = Object.freeze({
  0:'NULL', 1:'PROGBITS', 2:'SYMTAB', 3:'STRTAB', 4:'RELA', 5:'HASH', 6:'DYNAMIC', 7:'NOTE', 8:'NOBITS',
  9:'REL', 10:'SHLIB', 11:'DYNSYM', 14:'INIT_ARRAY', 15:'FINI_ARRAY', 16:'PREINIT_ARRAY', 17:'GROUP', 18:'SYMTAB_SHNDX'
});

function assertBuffer(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new Error('ELF 输入必须是 Buffer');
  if (buffer.length < 52) throw new Error('文件过小，不是有效 ELF');
  if (buffer.length > MAX_ELF_BYTES) throw new Error(`ELF 超过 ${MAX_ELF_BYTES} bytes 分析上限`);
  if (!(buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46)) throw new Error('文件 Magic 不是 ELF');
}

function reader(buffer, little) {
  const need = (offset, size) => {
    if (!Number.isInteger(offset) || offset < 0 || offset + size > buffer.length) throw new Error(`ELF 读取越界 @0x${Math.max(0, offset).toString(16)}`);
  };
  return {
    u8(offset) { need(offset,1); return buffer[offset]; },
    u16(offset) { need(offset,2); return little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset); },
    u32(offset) { need(offset,4); return little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset); },
    u64(offset) { need(offset,8); return little ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset); }
  };
}

function safeNumber(value, label) {
  const big = typeof value === 'bigint' ? value : BigInt(value);
  if (big < 0n || big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} 超出安全整数范围`);
  return Number(big);
}

function hex(value) {
  const big = typeof value === 'bigint' ? value : BigInt(value || 0);
  return `0x${big.toString(16)}`;
}

function sanitizeId(value) {
  return String(value || '').replace(/[^A-Za-z0-9_.$?@-]/g, '_').slice(0, 180) || 'anon';
}

function readCString(buffer, start, limitEnd = buffer.length, maxLen = 4096) {
  if (!Number.isInteger(start) || start < 0 || start >= limitEnd || start >= buffer.length) return '';
  const endLimit = Math.min(buffer.length, limitEnd, start + maxLen);
  let end = start;
  while (end < endLimit && buffer[end] !== 0) end += 1;
  return buffer.subarray(start, end).toString('utf8').replace(/\u0000/g, '');
}

function parseHeader(buffer) {
  assertBuffer(buffer);
  const elfClass = buffer[4];
  const data = buffer[5];
  if (![1,2].includes(elfClass)) throw new Error(`不支持 ELF class=${elfClass}`);
  if (![1,2].includes(data)) throw new Error(`不支持 ELF data encoding=${data}`);
  const bits = elfClass === 2 ? 64 : 32;
  const little = data === 1;
  const r = reader(buffer, little);
  const header = {
    bits,
    littleEndian: little,
    endian: little ? 'little' : 'big',
    osAbi: buffer[7],
    abiVersion: buffer[8],
    type: r.u16(16),
    machine: r.u16(18),
    version: r.u32(20)
  };
  if (bits === 64) {
    Object.assign(header, {
      entry:r.u64(24), phoff:r.u64(32), shoff:r.u64(40), flags:r.u32(48), ehsize:r.u16(52),
      phentsize:r.u16(54), phnum:r.u16(56), shentsize:r.u16(58), shnum:r.u16(60), shstrndx:r.u16(62)
    });
  } else {
    Object.assign(header, {
      entry:BigInt(r.u32(24)), phoff:BigInt(r.u32(28)), shoff:BigInt(r.u32(32)), flags:r.u32(36), ehsize:r.u16(40),
      phentsize:r.u16(42), phnum:r.u16(44), shentsize:r.u16(46), shnum:r.u16(48), shstrndx:r.u16(50)
    });
  }
  header.typeName = TYPE_NAMES[header.type] || `TYPE_${header.type}`;
  header.machineName = MACHINE_NAMES[header.machine] || `MACHINE_${header.machine}`;
  return { header, r };
}

function parseSectionEntry(buffer, r, header, index) {
  const offset = safeNumber(header.shoff, 'section table offset') + index * header.shentsize;
  const min = header.bits === 64 ? 64 : 40;
  if (header.shentsize < min) throw new Error(`section header entry size ${header.shentsize} 小于 ELF${header.bits} 标准最小值 ${min}`);
  if (offset < 0 || offset + min > buffer.length) throw new Error(`section header #${index} 越界`);
  if (header.bits === 64) {
    return {
      index, nameOffset:r.u32(offset), type:r.u32(offset+4), flags:r.u64(offset+8), addr:r.u64(offset+16), fileOffset:r.u64(offset+24),
      size:r.u64(offset+32), link:r.u32(offset+40), info:r.u32(offset+44), addralign:r.u64(offset+48), entsize:r.u64(offset+56)
    };
  }
  return {
    index, nameOffset:r.u32(offset), type:r.u32(offset+4), flags:BigInt(r.u32(offset+8)), addr:BigInt(r.u32(offset+12)), fileOffset:BigInt(r.u32(offset+16)),
    size:BigInt(r.u32(offset+20)), link:r.u32(offset+24), info:r.u32(offset+28), addralign:BigInt(r.u32(offset+32)), entsize:BigInt(r.u32(offset+36))
  };
}

function parseSections(buffer, r, header) {
  if (header.shoff === 0n || header.shentsize === 0) return [];
  let shnum = header.shnum;
  let shstrndx = header.shstrndx;
  const section0 = parseSectionEntry(buffer, r, header, 0);
  if (shnum === 0) shnum = safeNumber(section0.size, 'extended section count');
  if (shstrndx === 0xffff) shstrndx = section0.link;
  if (shnum > MAX_SECTIONS) throw new Error(`ELF section 数 ${shnum} 超过 ${MAX_SECTIONS} 上限`);
  const sections = [];
  for (let index = 0; index < shnum; index += 1) sections.push(parseSectionEntry(buffer, r, header, index));
  const shstr = sections[shstrndx];
  let shstrStart = null;
  let shstrEnd = null;
  if (shstr && shstr.type === SHT.STRTAB) {
    shstrStart = safeNumber(shstr.fileOffset, 'shstrtab offset');
    shstrEnd = Math.min(buffer.length, shstrStart + safeNumber(shstr.size, 'shstrtab size'));
  }
  for (const section of sections) {
    section.name = shstrStart == null ? `section_${section.index}` : readCString(buffer, shstrStart + section.nameOffset, shstrEnd, 1024) || `section_${section.index}`;
    section.typeName = SECTION_TYPE_NAMES[section.type] || `TYPE_${section.type}`;
    section.alloc = Boolean(section.flags & SHF.ALLOC);
    section.writable = Boolean(section.flags & SHF.WRITE);
    section.executable = Boolean(section.flags & SHF.EXECINSTR);
    section.fileBacked = section.type !== SHT.NOBITS && section.size > 0n;
    section.truncated = false;
    if (section.fileBacked) {
      try {
        const start = safeNumber(section.fileOffset, `${section.name} offset`);
        const size = safeNumber(section.size, `${section.name} size`);
        section.truncated = start < 0 || start > buffer.length || start + size > buffer.length;
      } catch { section.truncated = true; }
    }
  }
  return sections;
}

function sectionForAddress(sections, address) {
  const a = typeof address === 'bigint' ? address : BigInt(address || 0);
  return sections.find((section) => section.alloc && section.size > 0n && a >= section.addr && a < section.addr + section.size) || null;
}

function sectionBytes(buffer, section, relativeOffset = 0, size = null) {
  if (!section?.fileBacked || section.truncated) return null;
  const base = safeNumber(section.fileOffset, `${section.name} offset`);
  const total = safeNumber(section.size, `${section.name} size`);
  const rel = Math.max(0, Number(relativeOffset) || 0);
  if (rel > total) return null;
  const length = size == null ? total - rel : Math.max(0, Math.min(Number(size) || 0, total - rel));
  if (base + rel + length > buffer.length) return null;
  return buffer.subarray(base + rel, base + rel + length);
}

function parseSymbols(buffer, r, header, sections) {
  const symbols = [];
  for (const section of sections) {
    if (![SHT.SYMTAB, SHT.DYNSYM].includes(section.type) || !section.fileBacked || section.truncated) continue;
    const strtab = sections[section.link];
    if (!strtab || strtab.type !== SHT.STRTAB || !strtab.fileBacked || strtab.truncated) continue;
    const entrySize = Number(section.entsize || 0n) || (header.bits === 64 ? 24 : 16);
    const min = header.bits === 64 ? 24 : 16;
    if (entrySize < min) continue;
    const table = sectionBytes(buffer, section);
    const strings = sectionBytes(buffer, strtab);
    if (!table || !strings) continue;
    const count = Math.min(Math.floor(table.length / entrySize), MAX_SYMBOLS - symbols.length);
    const base = safeNumber(section.fileOffset, `${section.name} offset`);
    for (let index = 0; index < count; index += 1) {
      const off = base + index * entrySize;
      let nameOffset, info, other, shndx, value, size;
      if (header.bits === 64) {
        nameOffset = r.u32(off); info = r.u8(off+4); other = r.u8(off+5); shndx = r.u16(off+6); value = r.u64(off+8); size = r.u64(off+16);
      } else {
        nameOffset = r.u32(off); value = BigInt(r.u32(off+4)); size = BigInt(r.u32(off+8)); info = r.u8(off+12); other = r.u8(off+13); shndx = r.u16(off+14);
      }
      const name = nameOffset < strings.length ? readCString(strings, nameOffset, strings.length, 2048) : '';
      symbols.push({
        table:section.name, index, name, info, binding:info >> 4, type:info & 0xf, other, shndx, value, size,
        section:shndx < sections.length ? sections[shndx]?.name || null : null
      });
      if (symbols.length >= MAX_SYMBOLS) break;
    }
    if (symbols.length >= MAX_SYMBOLS) break;
  }
  return symbols;
}

function printableRatio(bytes) {
  if (!bytes?.length) return 0;
  let printable = 0;
  for (const value of bytes) if ((value >= 0x20 && value <= 0x7e) || value === 0x09) printable += 1;
  return printable / bytes.length;
}

function asciiPreview(bytes) {
  return [...bytes].map((value) => value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : '.').join('');
}

function bytesHex(bytes) {
  return [...bytes].map((value) => value.toString(16).padStart(2,'0')).join(' ');
}

function objectFromRange(buffer, section, address, size, name, source, extra = {}) {
  const relative = safeNumber(address - section.addr, `${name} relative address`);
  const fullSize = Math.max(0, Math.min(safeNumber(size, `${name} size`), safeNumber(section.size - BigInt(relative), `${name} remaining section size`)));
  const previewSize = Math.min(fullSize, MAX_PREVIEW_BYTES);
  const preview = sectionBytes(buffer, section, relative, previewSize);
  const bytes = preview ? [...preview] : null;
  let kind = extra.kind || 'byte_array';
  if (preview && fullSize > 0 && printableRatio(preview.subarray(0, Math.min(preview.length, Math.max(1, fullSize - 1)))) >= 0.88 && (preview.includes(0) || fullSize <= preview.length)) kind = extra.kind || 'string';
  return {
    id:`obj_${sanitizeId(name || hex(address))}`,
    name:name || `data_${address.toString(16)}`,
    address:hex(address),
    section:section.name,
    kind,
    size:fullSize,
    bytesHex:bytes ? bytesHex(bytes) : null,
    ascii:bytes ? asciiPreview(bytes) : null,
    bytesPreviewSize:previewSize,
    bytesTruncated:fullSize > previewSize,
    fields:[],
    evidence:[],
    cellEvidence:[],
    structuralName:null,
    semanticSuggestions:[],
    source,
    ...extra
  };
}

function buildSymbolObjects(buffer, header, sections, symbols) {
  const objects = [];
  const seenAddress = new Set();
  const candidates = symbols.filter((symbol) => {
    const section = sections[symbol.shndx];
    if (!section || !section.alloc || section.executable || symbol.value === 0n) return false;
    return symbol.type === STT.OBJECT || (symbol.type === STT.NOTYPE && symbol.size > 0n);
  });
  const bySection = new Map();
  for (const symbol of candidates) {
    if (!bySection.has(symbol.shndx)) bySection.set(symbol.shndx, []);
    bySection.get(symbol.shndx).push(symbol);
  }
  for (const rows of bySection.values()) rows.sort((a,b) => a.value < b.value ? -1 : a.value > b.value ? 1 : 0);
  for (const [sectionIndex, rows] of bySection.entries()) {
    const section = sections[sectionIndex];
    for (let index = 0; index < rows.length && objects.length < MAX_OBJECTS; index += 1) {
      const symbol = rows[index];
      if (seenAddress.has(symbol.value.toString())) continue;
      let size = symbol.size;
      if (size === 0n) {
        const next = rows[index+1];
        if (next && next.value > symbol.value) size = next.value - symbol.value;
      }
      if (size <= 0n || symbol.value < section.addr || symbol.value >= section.addr + section.size) continue;
      if (symbol.value + size > section.addr + section.size) size = section.addr + section.size - symbol.value;
      const object = objectFromRange(buffer, section, symbol.value, size, symbol.name || `sym_${symbol.value.toString(16)}`, 'symbol', {
        symbol:{ binding:symbol.binding, type:symbol.type, table:symbol.table }
      });
      object.evidence.push({ kind:'symbol', text:`${symbol.table}: ${symbol.name || '<anonymous>'} size=${size.toString()}` });
      objects.push(object);
      seenAddress.add(symbol.value.toString());
    }
  }
  return objects;
}

function objectRangeContains(object, address) {
  try {
    const start = BigInt(object.address);
    return address >= start && address < start + BigInt(object.size || 0);
  } catch { return false; }
}

function addStringObjects(buffer, sections, objects) {
  let totalScanned = 0;
  let added = 0;
  for (const section of sections) {
    if (added >= MAX_STRING_OBJECTS || objects.length >= MAX_OBJECTS || totalScanned >= MAX_TOTAL_STRING_SCAN_BYTES) break;
    if (!section.alloc || section.executable || !section.fileBacked || section.truncated || section.size <= 0n) continue;
    const totalSize = safeNumber(section.size, `${section.name} size`);
    const scanSize = Math.min(totalSize, MAX_SCAN_BYTES_PER_SECTION, MAX_TOTAL_STRING_SCAN_BYTES - totalScanned);
    const bytes = sectionBytes(buffer, section, 0, scanSize);
    if (!bytes) continue;
    totalScanned += bytes.length;
    let start = -1;
    const flush = (end, nulTerminated) => {
      if (start < 0) return;
      const len = end - start;
      if (len >= 5) {
        const address = section.addr + BigInt(start);
        const already = objects.some((object) => objectRangeContains(object, address));
        if (!already && added < MAX_STRING_OBJECTS && objects.length < MAX_OBJECTS) {
          const size = BigInt(len + (nulTerminated ? 1 : 0));
          const obj = objectFromRange(buffer, section, address, size, `str_${address.toString(16)}`, 'ascii-scan', { kind:'string' });
          obj.evidence.push({ kind:'string-scan', text:`ASCII run ${len} bytes${nulTerminated ? ' + NUL' : ''}` });
          objects.push(obj); added += 1;
        }
      }
      start = -1;
    };
    for (let index = 0; index < bytes.length; index += 1) {
      const value = bytes[index];
      if (value >= 0x20 && value <= 0x7e) {
        if (start < 0) start = index;
      } else {
        flush(index, value === 0);
      }
    }
    flush(bytes.length, false);
  }
  return { added, scannedBytes:totalScanned };
}

function pointerValue(buffer, header, section, relativeOffset) {
  const size = header.bits === 64 ? 8 : 4;
  const bytes = sectionBytes(buffer, section, relativeOffset, size);
  if (!bytes || bytes.length < size) return null;
  return header.bits === 64
    ? (header.littleEndian ? bytes.readBigUInt64LE(0) : bytes.readBigUInt64BE(0))
    : BigInt(header.littleEndian ? bytes.readUInt32LE(0) : bytes.readUInt32BE(0));
}

function ensureTargetObject(buffer, sections, objects, address, sizeHint = 1n, source = 'pointer-target') {
  let object = objects.find((item) => {
    try { return BigInt(item.address) === address; } catch { return false; }
  });
  if (object) return object;
  const section = sectionForAddress(sections, address);
  if (!section || section.executable) return null;
  let size = sizeHint > 0n ? sizeHint : 1n;
  if (address + size > section.addr + section.size) size = section.addr + section.size - address;
  if (size <= 0n) return null;
  object = objectFromRange(buffer, section, address, size, `byte_${address.toString(16)}`, source, { kind:size > 1n ? 'byte_array' : 'byte' });
  objects.push(object);
  return object;
}

function addRelation(relations, seen, relation) {
  if (relations.length >= MAX_RELATIONS) return null;
  const key = `${relation.source}|${relation.target}|${relation.type}|${relation.location || ''}`;
  if (seen.has(key)) return null;
  const item = { id:`rel_${relations.length+1}`, confidence:1, evidence:[], ...relation };
  relations.push(item); seen.add(key); return item;
}

function detectGoBinary(sections, symbols, buffer) {
  const names = new Set(sections.map((section) => section.name));
  if (names.has('.gopclntab') || names.has('.go.buildinfo')) return { likely:true, reason:'Go-specific section present' };
  if (symbols.some((symbol) => /^runtime\.|^main\.main$|^type:/.test(symbol.name || ''))) return { likely:true, reason:'Go runtime symbols present' };
  const probe = buffer.subarray(0, Math.min(buffer.length, 8 * 1024 * 1024)).toString('latin1');
  if (probe.includes('Go build ID:') || probe.includes('runtime.main')) return { likely:true, reason:'Go build marker present' };
  return { likely:false, reason:null };
}

function detectSliceCandidates(buffer, header, sections, symbols, objects, relations, relationSeen) {
  const pointerSize = header.bits === 64 ? 8 : 4;
  const go = detectGoBinary(sections, symbols, buffer);
  let count = 0;
  const scanSections = sections.filter((section) => section.alloc && !section.executable && section.fileBacked && !section.truncated && (section.writable || /(?:^|\.)data$|\.data\.|noptrdata/i.test(section.name)));
  for (const section of scanSections) {
    const sectionSize = safeNumber(section.size, `${section.name} size`);
    const maxScan = Math.min(sectionSize, 8 * 1024 * 1024);
    const alignment = Math.max(pointerSize, Number(section.addralign > 0n && section.addralign < 64n ? section.addralign : BigInt(pointerSize)));
    for (let rel = 0; rel + pointerSize * 3 <= maxScan && objects.length < MAX_OBJECTS; rel += alignment) {
      const ptr = pointerValue(buffer, header, section, rel);
      const lenValue = pointerValue(buffer, header, section, rel + pointerSize);
      const capValue = pointerValue(buffer, header, section, rel + pointerSize * 2);
      if (ptr == null || lenValue == null || capValue == null) continue;
      if (lenValue <= 0n || capValue < lenValue || capValue > 0x1000000n) continue;
      if (capValue > lenValue * 64n) continue;
      const targetSection = sectionForAddress(sections, ptr);
      if (!targetSection || targetSection.executable) continue;
      const targetRemaining = targetSection.size - (ptr - targetSection.addr);
      if (targetRemaining < lenValue) continue;
      let score = 0.32;
      if (go.likely) score += 0.26;
      if (section.writable) score += 0.12;
      if (lenValue === capValue) score += 0.12;
      if (/rodata|noptrdata/i.test(targetSection.name)) score += 0.10;
      if (lenValue <= 0x10000n) score += 0.05;
      score = Math.min(0.99, score);
      if (score < (go.likely ? 0.72 : 0.90)) continue;
      const sourceAddress = section.addr + BigInt(rel);
      let object = objects.find((item) => {
        try { return BigInt(item.address) === sourceAddress; } catch { return false; }
      });
      const target = ensureTargetObject(buffer, sections, objects, ptr, lenValue, 'slice-backing');
      if (!target) continue;
      if (!object) {
        object = objectFromRange(buffer, section, sourceAddress, BigInt(pointerSize*3), `slice_${sourceAddress.toString(16)}`, 'slice-scan', { kind:go.likely ? 'go_slice' : 'slice_candidate' });
        objects.push(object);
      }
      object.kind = go.likely ? 'go_slice' : 'slice_candidate';
      object.structuralName = `${go.likely ? 'byteSlice' : 'sliceCandidate'}_${sourceAddress.toString(16)}`;
      object.pointsTo = target.id;
      object.fields = [
        { offset:0, name:'data', value:hex(ptr), target:target.id },
        { offset:pointerSize, name:'len', value:safeNumber(lenValue, 'slice len') },
        { offset:pointerSize*2, name:'cap', value:safeNumber(capValue, 'slice cap') }
      ];
      object.evidence = (object.evidence || []).filter((item) => item.kind !== 'slice-structure');
      object.evidence.push({ kind:'slice-structure', text:`${go.likely ? 'Go' : 'generic'} slice candidate: ptr=${hex(ptr)}, len=${lenValue}, cap=${capValue}; ${go.reason || 'no Go marker'}` });
      addRelation(relations, relationSeen, { source:object.id, target:target.id, type:'POINTS_TO', confidence:score, evidence:[`ptr=${hex(ptr)} targets ${targetSection.name}`] });
      addRelation(relations, relationSeen, { source:object.id, target:target.id, type:'LENGTH_OF', value:safeNumber(lenValue,'slice len'), confidence:score, evidence:[`len=${lenValue}, cap=${capValue}`] });
      count += 1;
      if (count >= 512) break;
    }
    if (count >= 512) break;
  }
  return { count, go };
}

function classifySymbolObjectPointers(buffer, header, sections, objects, relations, relationSeen) {
  const pointerSize = header.bits === 64 ? 8 : 4;
  for (const object of objects.slice()) {
    if (object.size < pointerSize || ['go_slice','slice_candidate'].includes(object.kind)) continue;
    const section = sections.find((item) => item.name === object.section);
    if (!section || !section.fileBacked || section.truncated) continue;
    const address = BigInt(object.address);
    const rel = safeNumber(address - section.addr, 'object relative offset');
    const ptr = pointerValue(buffer, header, section, rel);
    if (ptr == null) continue;
    const targetSection = sectionForAddress(sections, ptr);
    if (!targetSection || targetSection.executable) continue;
    const target = ensureTargetObject(buffer, sections, objects, ptr, 1n, 'pointer-target');
    if (!target) continue;
    if (object.size === pointerSize) object.kind = 'pointer';
    object.pointsTo = object.pointsTo || target.id;
    addRelation(relations, relationSeen, { source:object.id, target:target.id, type:'POINTS_TO', confidence:0.86, evidence:[`first pointer-sized value ${hex(ptr)} falls in ${targetSection.name}`] });
  }
}

function parseRelocations(buffer, r, header, sections, symbols, objects, relations, relationSeen) {
  let count = 0;
  const symbolTables = new Map();
  for (const section of sections) {
    if (![SHT.SYMTAB,SHT.DYNSYM].includes(section.type)) continue;
    symbolTables.set(section.index, symbols.filter((symbol) => symbol.table === section.name));
  }
  const functions = symbols.filter((symbol) => symbol.type === STT.FUNC && symbol.value > 0n && symbol.size > 0n);
  const objectByName = new Map(objects.map((object) => [object.name, object]));
  const objectAt = (address) => objects.find((object) => objectRangeContains(object,address)) || null;
  const functionAt = (address) => functions.find((fn) => address >= fn.value && address < fn.value + fn.size) || null;
  for (const relocSection of sections) {
    if (![SHT.RELA,SHT.REL].includes(relocSection.type) || !relocSection.fileBacked || relocSection.truncated) continue;
    const tableSymbols = symbolTables.get(relocSection.link) || [];
    const targetSection = sections[relocSection.info] || null;
    const min = header.bits === 64 ? (relocSection.type === SHT.RELA ? 24 : 16) : (relocSection.type === SHT.RELA ? 12 : 8);
    const entrySize = Number(relocSection.entsize || 0n) || min;
    if (entrySize < min) continue;
    const base = safeNumber(relocSection.fileOffset, `${relocSection.name} offset`);
    const size = safeNumber(relocSection.size, `${relocSection.name} size`);
    const entries = Math.min(Math.floor(size / entrySize), 200000);
    for (let index=0; index<entries && count<200000; index+=1) {
      const off = base + index*entrySize;
      let rOffset, rInfo, symIndex, relType;
      if (header.bits === 64) {
        rOffset = r.u64(off); rInfo = r.u64(off+8); symIndex = Number(rInfo >> 32n); relType = Number(rInfo & 0xffffffffn);
      } else {
        rOffset = BigInt(r.u32(off)); rInfo = BigInt(r.u32(off+4)); symIndex = Number(rInfo >> 8n); relType = Number(rInfo & 0xffn);
      }
      const symbol = tableSymbols[symIndex];
      if (!symbol?.name) { count += 1; continue; }
      let target = objectByName.get(symbol.name) || objects.find((object) => {
        try { return BigInt(object.address) === symbol.value; } catch { return false; }
      });
      if (!target && symbol.shndx < sections.length && symbol.value > 0n) {
        const symbolSection = sections[symbol.shndx];
        if (symbolSection?.alloc && !symbolSection.executable) {
          target = ensureTargetObject(buffer, sections, objects, symbol.value, symbol.size > 0n ? symbol.size : 1n, 'relocation-symbol');
          if (target && symbol.name && /^byte_/.test(target.name)) target.name = symbol.name;
        }
      }
      if (!target) { count += 1; continue; }
      const sourceAddress = header.type === 1 && targetSection ? targetSection.addr + rOffset : rOffset;
      const fn = functionAt(sourceAddress);
      const sourceObject = objectAt(sourceAddress);
      const sourceId = fn ? `fn_${sanitizeId(fn.name || hex(fn.value))}` : sourceObject?.id || `addr_${sourceAddress.toString(16)}`;
      const type = fn ? 'REFERENCES' : sourceObject ? 'RELOCATES_TO' : 'RELOCATION_REF';
      addRelation(relations, relationSeen, {
        source:sourceId, sourceLabel:fn?.name || sourceObject?.name || hex(sourceAddress), target:target.id, type, location:hex(sourceAddress), confidence:0.93,
        evidence:[`${relocSection.name} type=${relType} symbol=${symbol.name}`]
      });
      count += 1;
    }
  }
  return { count, functions: functions.length };
}

function publicSection(section, objects) {
  return {
    index:section.index, name:section.name, type:section.typeName, address:hex(section.addr), size:safeNumber(section.size, `${section.name} size`),
    fileOffset:hex(section.fileOffset), alloc:section.alloc, writable:section.writable, executable:section.executable,
    fileBacked:section.fileBacked, truncated:section.truncated,
    objectIds:objects.filter((object) => object.section === section.name).map((object) => object.id)
  };
}

function analyzeElfBinary(buffer, fileName = 'binary.elf') {
  const { header, r } = parseHeader(buffer);
  const sections = parseSections(buffer, r, header);
  const symbols = parseSymbols(buffer, r, header, sections);
  const objects = buildSymbolObjects(buffer, header, sections, symbols);
  const stringScan = addStringObjects(buffer, sections, objects);
  const relations = [];
  const relationSeen = new Set();
  const sliceScan = detectSliceCandidates(buffer, header, sections, symbols, objects, relations, relationSeen);
  classifySymbolObjectPointers(buffer, header, sections, objects, relations, relationSeen);
  const relocationScan = parseRelocations(buffer, r, header, sections, symbols, objects, relations, relationSeen);
  const importantRelations = relations.filter((relation) => ['POINTS_TO','LENGTH_OF','REFERENCES','RELOCATES_TO'].includes(relation.type));
  const functionCount = symbols.filter((symbol) => symbol.type === STT.FUNC && symbol.value > 0n).length;
  const objectCountBeforeCap = objects.length;
  const publicObjects = objects.slice(0, MAX_OBJECTS);
  return {
    schema:'newcyber.binary-data-graph.v2',
    source:{
      kind:'elf', fileName:String(fileName || 'binary.elf').slice(0,240), byteLength:buffer.length, parser:'deterministic-elf-v0.2',
      elf:{ bits:header.bits, endian:header.endian, type:header.typeName, machine:header.machineName, entry:hex(header.entry), goLikely:sliceScan.go.likely, goEvidence:sliceScan.go.reason }
    },
    summary:{
      sections:sections.length, objects:publicObjects.length, operations:0, relations:relations.length, importantRelations:importantRelations.length,
      semanticCandidates:0, recoverableRelations:0, symbols:symbols.length, functions:functionCount, relocations:relocationScan.count,
      strings:stringScan.added, sliceCandidates:sliceScan.count
    },
    sections:sections.map((section) => publicSection(section, publicObjects)),
    objects:publicObjects,
    operations:[], relations, semanticCandidates:[], recoverableRelations:[],
    elf:{
      header:{ bits:header.bits, endian:header.endian, type:header.typeName, machine:header.machineName, entry:hex(header.entry), flags:`0x${header.flags.toString(16)}`, sectionHeaderOffset:hex(header.shoff) },
      symbolTables:sections.filter((section) => [SHT.SYMTAB,SHT.DYNSYM].includes(section.type)).map((section) => section.name),
      goLikely:sliceScan.go
    },
    notes:[
      'Batch26 直接解析 ELF32/ELF64 section、symbol、relocation 和静态数据，不执行附件。',
      '原始 ELF 当前先恢复 Physical/Object/Relation；没有内置反汇编器时不会伪造 XOR/CMP Expression IR。需要表达式关系时可继续使用 textual listing 模式。',
      `${sliceScan.go.likely ? '检测到 Go 证据，slice 扫描按 Go 结构提高置信度。' : '未检测到明确 Go 标记；generic slice candidate 使用更高阈值。'}`,
      objectCountBeforeCap > MAX_OBJECTS ? `对象数量超过 ${MAX_OBJECTS}，输出已截断。` : '对象输出未触发上限。'
    ]
  };
}

module.exports = {
  MAX_ELF_BYTES,
  parseHeader,
  parseSections,
  parseSymbols,
  analyzeElfBinary
};