'use strict';

const { analyzeBinaryDataListing } = require('./binary_data_graph');

const SCHEMA = 'newcyber.ida-snapshot.v1';
const MAX_ITEMS = 300000;
const MAX_FUNCTIONS = 60000;
const MAX_LISTING_CHARS = 2 * 1024 * 1024;

function address(value) {
  try { return BigInt(String(value || '0')); } catch { return null; }
}

function normalizeAddress(value) {
  const v = address(value);
  return v == null ? null : `0x${v.toString(16)}`;
}

function safeId(value) {
  return String(value || '').replace(/[^A-Za-z0-9_.$?@-]/g, '_').slice(0, 180) || 'anon';
}

function validateSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') throw new Error('IDA Snapshot 必须是 JSON object');
  if (snapshot.schema !== SCHEMA) throw new Error(`不支持 IDA Snapshot schema: ${snapshot.schema || '<missing>'}`);
  if (!Array.isArray(snapshot.segments) || !Array.isArray(snapshot.items) || !Array.isArray(snapshot.functions)) throw new Error('IDA Snapshot 缺少 segments/items/functions');
  if (snapshot.items.length > MAX_ITEMS) throw new Error(`IDA Snapshot items 超过 ${MAX_ITEMS} 上限`);
  if (snapshot.functions.length > MAX_FUNCTIONS) throw new Error(`IDA Snapshot functions 超过 ${MAX_FUNCTIONS} 上限`);
  return snapshot;
}

function itemListingLine(item) {
  const ea = address(item.address);
  if (ea == null) return null;
  const seg = String(item.segment || '.text');
  const prefix = `${seg}:${ea.toString(16).padStart(16, '0').toUpperCase()}`;
  let disasm = String(item.disasm || '').trim();
  if (!disasm && item.mnemonic) disasm = `${item.mnemonic} ${(item.operands || []).join(', ')}`.trim();
  if (!disasm) return null;
  if (item.kind === 'data' && item.name && /^(?:db|dw|dd|dq)\b/i.test(disasm)) disasm = `${item.name} ${disasm}`;
  const commentParts = [];
  if (Array.isArray(item.comments)) commentParts.push(...item.comments.filter(Boolean).map(String));
  if (item.function) commentParts.push(`FUNC:${item.function}`);
  return `${prefix} ${disasm}${commentParts.length ? ` ; ${commentParts.join(' | ')}` : ''}`;
}

function buildListing(snapshot) {
  const lines = [];
  let chars = 0;
  const functionByStart = new Map(snapshot.functions.map((fn) => [normalizeAddress(fn.start), fn]).filter(([key]) => key));
  const seenFunctions = new Set();
  for (const item of snapshot.items) {
    const key = normalizeAddress(item.address);
    const fn = functionByStart.get(key);
    if (fn && !seenFunctions.has(key)) {
      const seg = String(item.segment || '.text');
      const proc = `${seg}:${address(item.address).toString(16).padStart(16, '0').toUpperCase()} ${fn.name || `sub_${address(item.address).toString(16)}`} proc near`;
      if (chars + proc.length + 1 <= MAX_LISTING_CHARS) { lines.push(proc); chars += proc.length + 1; }
      seenFunctions.add(key);
    }
    const line = itemListingLine(item);
    if (!line) continue;
    if (chars + line.length + 1 > MAX_LISTING_CHARS) break;
    lines.push(line); chars += line.length + 1;
  }
  return { text:lines.join('\n'), lineCount:lines.length, truncated:chars >= MAX_LISTING_CHARS };
}

function objectContains(object, ea) {
  const start = address(object.address);
  if (start == null || ea == null) return false;
  return ea >= start && ea < start + BigInt(Math.max(1, Number(object.size) || 1));
}

function relationKey(relation) {
  return `${relation.source}|${relation.target}|${relation.type}|${relation.location || ''}`;
}

function enrichFromStructuredXrefs(result, snapshot) {
  const relations = result.relations || (result.relations = []);
  const seen = new Set(relations.map(relationKey));
  const objectFor = (ea) => result.objects.find((object) => objectContains(object, ea)) || null;
  const functionFor = (ea) => snapshot.functions.find((fn) => {
    const start = address(fn.start); const end = address(fn.end);
    return start != null && end != null && ea >= start && ea < end;
  }) || null;
  let added = 0;
  for (const item of snapshot.items) {
    const itemEa = address(item.address);
    if (itemEa == null) continue;
    const sourceFn = functionFor(itemEa);
    for (const xref of Array.isArray(item.xrefsFrom) ? item.xrefsFrom : []) {
      const targetEa = address(xref.to);
      if (targetEa == null) continue;
      const targetObject = objectFor(targetEa);
      if (!targetObject) continue;
      const source = sourceFn ? `fn_${safeId(sourceFn.name || sourceFn.start)}` : `addr_${itemEa.toString(16)}`;
      const relation = {
        id:`rel_${relations.length + 1}`,
        source,
        sourceLabel:sourceFn?.name || normalizeAddress(item.address),
        target:targetObject.id,
        type:xref.isCode ? 'READS' : 'XREF_TO',
        location:normalizeAddress(item.address),
        confidence:0.99,
        evidence:[`IDA XREF type=${xref.type} ${normalizeAddress(xref.from)} → ${normalizeAddress(xref.to)}`],
        ida:{ type:Number(xref.type) || 0, isCode:Boolean(xref.isCode) }
      };
      const key = relationKey(relation);
      if (seen.has(key)) continue;
      relations.push(relation); seen.add(key); added += 1;
    }
  }
  return added;
}

function enrichObjectEvidence(result, snapshot) {
  for (const object of result.objects || []) {
    const start = address(object.address);
    if (start == null) continue;
    const matches = snapshot.items.filter((item) => {
      const ea = address(item.address);
      return ea != null && objectContains(object, ea) && item.kind === 'data';
    }).slice(0, 64);
    if (!matches.length) continue;
    object.evidence = object.evidence || [];
    const named = matches.find((item) => item.name);
    if (named && (!object.name || /^data_/.test(object.name))) object.name = named.name;
    for (const item of matches) {
      if (item.bytesHex && !object.bytesHex) object.bytesHex = String(item.bytesHex).trim();
      for (const comment of Array.isArray(item.comments) ? item.comments : []) object.evidence.push({ kind:'ida-comment', text:String(comment), address:normalizeAddress(item.address) });
      if (Array.isArray(item.xrefsTo) && item.xrefsTo.length) object.evidence.push({ kind:'ida-xref', text:`${item.xrefsTo.length} IDA xref(s) to ${normalizeAddress(item.address)}` });
    }
  }
}

function analyzeIdaSnapshot(input) {
  const snapshot = validateSnapshot(typeof input === 'string' ? JSON.parse(input) : input);
  const listing = buildListing(snapshot);
  if (!listing.text.trim()) throw new Error('IDA Snapshot 没有可分析的 listing/items');
  const result = analyzeBinaryDataListing(listing.text);
  enrichObjectEvidence(result, snapshot);
  const structuredXrefs = enrichFromStructuredXrefs(result, snapshot);
  const important = result.relations.filter((relation) => ['POINTS_TO','XORS_WITH','COMPARES_WITH','LENGTH_OF','READS','XREF_TO'].includes(relation.type));
  result.schema = 'newcyber.binary-data-graph.v2';
  result.source = {
    kind:'ida-snapshot',
    parser:'ida-snapshot-bridge-v0.1',
    fileName:snapshot.ida?.inputFile || '',
    ida:{
      version:snapshot.ida?.version || 'unknown',
      processor:snapshot.ida?.processor || 'unknown',
      bitness:Number(snapshot.ida?.bitness) || 0,
      imageBase:snapshot.ida?.imageBase || null,
      inputMd5:snapshot.ida?.inputMd5 || null,
      exporterVersion:snapshot.exporterVersion || 'unknown'
    }
  };
  result.summary = {
    ...result.summary,
    functions:snapshot.functions.length,
    idaItems:snapshot.items.length,
    structuredXrefs,
    importantRelations:important.length
  };
  result.ida = {
    segments:snapshot.segments,
    functions:snapshot.functions,
    limits:snapshot.limits || {},
    exportedAt:snapshot.exportedAt || null
  };
  result.notes = [
    'IDA Snapshot 模式把 IDA 的 names/functions/xrefs/bytes 当作高置信事实源，再复用 NewCyber 的 Object/Relation/Expression 恢复。',
    'Snapshot 是离线 JSON；NewCyber 不连接 IDA、不执行目标程序，也不要求比赛时保持 IDA Bridge 服务在线。',
    listing.truncated || snapshot.limits?.listingTruncated ? 'Snapshot listing 触发长度上限；结构化 XREF/函数仍保留，但 Expression 覆盖可能不完整。' : 'Snapshot listing 未触发 NewCyber 长度上限。',
    ...(result.notes || [])
  ];
  return result;
}

module.exports = { SCHEMA, validateSnapshot, buildListing, analyzeIdaSnapshot };
