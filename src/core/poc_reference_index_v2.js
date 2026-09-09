'use strict';

const fsp = require('fs/promises');
const path = require('path');
const base = require('./poc_reference_index');

const DEFAULT_MAX_CVES = 50000;
const HARD_MAX_CVES = 120000;

async function mapLimit(items, limit, worker) {
  const out = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.max(1, Math.min(Number(limit) || 1, items.length || 1)) }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= items.length) break;
      out[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return out;
}

function inspectPocIndexHealth(index) {
  if (!index || index.schema !== base.INDEX_SCHEMA || !Array.isArray(index.entries)) {
    return { state:'broken', healthy:false, issues:['索引 schema/entries 不受支持'] };
  }
  const stats = index.stats || {};
  const issues = [];
  const parseErrors = Math.max(0, Number(stats.parseErrors) || 0);
  const availableCves = Number.isFinite(Number(stats.availableCves)) ? Number(stats.availableCves) : null;
  const indexedCves = Number(stats.cves) || index.entries.length;
  const truncated = Boolean(stats.truncated) || (availableCves != null && indexedCves < availableCves);
  const badEntries = index.entries.slice(0, 2000).filter((entry) => !/^CVE-\d{4}-\d{4,7}$/i.test(String(entry?.cve || '')) || !Array.isArray(entry?.repos) || !Array.isArray(entry?.keywords)).length;
  if (parseErrors) issues.push(`${parseErrors} 个 CVE JSON 解析失败`);
  if (truncated) issues.push(`索引预算截断：${indexedCves}/${availableCves ?? '?'} CVE`);
  if (badEntries) issues.push(`抽样发现 ${badEntries} 个结构异常 entry`);
  if (availableCves == null) issues.push('旧版缓存缺少 availableCves/coverage 统计，建议更新一次索引');
  let state = 'healthy';
  if (badEntries || parseErrors > Math.max(10, indexedCves * 0.01)) state = 'degraded';
  else if (truncated || availableCves == null || parseErrors) state = 'partial';
  return {
    state,
    healthy:state === 'healthy',
    issues,
    sourceRepository:index.source?.repository || base.SOURCE_REPOSITORY,
    indexedCves,
    availableCves,
    references:Number(stats.references) || 0,
    parseErrors,
    truncated,
    coverage:stats.coverage || null,
    selectionPolicy:stats.selectionPolicy || 'legacy/unknown'
  };
}

async function enumeratePocFiles(root, maxCves) {
  const rootEntries = await fsp.readdir(root, { withFileTypes:true });
  const years = rootEntries
    .filter((entry) => entry.isDirectory() && /^(?:19|20)\d{2}$/.test(entry.name))
    .map((entry) => entry.name)
    .sort((a,b) => Number(b) - Number(a));
  if (!years.length) throw new Error('未找到年份目录；请选择 nomi-sec/PoC-in-GitHub 仓库根目录');

  const byYear = [];
  let availableCves = 0;
  for (const year of years) {
    let entries;
    try { entries = await fsp.readdir(path.join(root, year), { withFileTypes:true }); }
    catch { continue; }
    const rows = entries
      .filter((entry) => entry.isFile())
      .map((entry) => ({ entry, match:entry.name.match(/^(CVE-\d{4}-\d{4,7})\.json$/i) }))
      .filter((item) => item.match)
      .map((item) => ({ cve:item.match[1].toUpperCase(), filePath:path.join(root, year, item.entry.name), year }))
      .sort((a,b) => b.cve.localeCompare(a.cve));
    availableCves += rows.length;
    byYear.push({ year, rows });
  }

  const files = [];
  const selectedByYear = new Map();
  for (const group of byYear) {
    for (const item of group.rows) {
      if (files.length >= maxCves) break;
      files.push(item);
      selectedByYear.set(group.year, (selectedByYear.get(group.year) || 0) + 1);
    }
    if (files.length >= maxCves) break;
  }
  const selectedYears = [...selectedByYear.keys()].sort((a,b) => Number(a)-Number(b));
  return {
    years,
    files,
    availableCves,
    truncated:files.length < availableCves,
    selectedYears,
    coverage:selectedYears.length ? { oldest:selectedYears[0], newest:selectedYears[selectedYears.length-1], years:selectedYears.length } : null
  };
}

async function buildPocIndexFromDirectory(rootPath, options = {}) {
  const root = path.resolve(String(rootPath || ''));
  const stat = await fsp.stat(root);
  if (!stat.isDirectory()) throw new Error('PoC-in-GitHub 索引源必须是目录');
  const maxCves = Math.max(1, Math.min(Number(options.maxCves) || DEFAULT_MAX_CVES, HARD_MAX_CVES));
  const inventory = await enumeratePocFiles(root, maxCves);

  let parseErrors = 0;
  const parsed = await mapLimit(inventory.files, Number(options.concurrency) || 24, async (item) => {
    try {
      const raw = await fsp.readFile(item.filePath, 'utf8');
      const records = JSON.parse(raw);
      if (!Array.isArray(records)) throw new Error('CVE JSON 顶层不是数组');
      return base.normalizeCveEntry(item.cve, records, options);
    } catch {
      parseErrors += 1;
      return null;
    }
  });
  const entries = parsed.filter(Boolean).sort((a,b) => a.cve.localeCompare(b.cve));
  const references = entries.reduce((sum,item) => sum + (Number(item.referenceCount) || 0), 0);
  const index = {
    schema:base.INDEX_SCHEMA,
    source:{
      repository:base.SOURCE_REPOSITORY,
      branch:'master',
      importedFrom:root,
      note:'仅索引仓库元数据（CVE、仓库名、说明、topics、stars/forks）；NewCyber 不自动下载或执行任何 PoC。'
    },
    generatedAt:new Date().toISOString(),
    stats:{
      years:inventory.years.length,
      cves:entries.length,
      availableCves:inventory.availableCves,
      references,
      parseErrors,
      truncated:inventory.truncated,
      maxCves,
      selectionPolicy:'newest-first',
      coverage:inventory.coverage,
      importer:'poc-index-v2'
    },
    entries
  };
  index.health = inspectPocIndexHealth(index);
  return index;
}

module.exports = {
  buildPocIndexFromDirectory,
  inspectPocIndexHealth,
  enumeratePocFiles
};
