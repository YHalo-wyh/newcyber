'use strict';

const fs = require('fs/promises');
const path = require('path');

const LOCATION_SCHEMA = 'newcyber.trusted-converter-location.v1';

function resolved(value) {
  const result = path.resolve(String(value || ''));
  if (!result || result === path.parse(result).root) throw new Error('路径无效');
  return result;
}

function containsPath(rootPath, targetPath) {
  const root = resolved(rootPath);
  const target = resolved(targetPath);
  const relative = path.relative(root, target);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function normalizedRoots(roots) {
  const out = [];
  const seen = new Set();
  for (const item of roots || []) {
    const value = typeof item === 'string' ? { path:item, label:'protected root' } : item;
    if (!value || typeof value.path !== 'string' || !value.path.trim()) continue;
    const root = resolved(value.path);
    const key = process.platform === 'win32' ? root.toLowerCase() : root;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ path:root, label:String(value.label || 'protected root').slice(0,128) });
  }
  return out;
}

async function canonicalPath(value, label) {
  const input = resolved(value);
  try {
    return { input, realPath:await fs.realpath(input) };
  } catch (error) {
    throw new Error(`${label} realpath 校验失败: ${error?.message || String(error)}`);
  }
}

async function validateTrustedConverterLocation(descriptor, roots = []) {
  if (!descriptor || typeof descriptor.filePath !== 'string' || !descriptor.filePath.trim()) {
    return { schema:LOCATION_SCHEMA, ok:false, code:'CONVERTER_LOCATION_GAP', detail:'缺少 trusted converter 路径' };
  }
  let converter;
  try { converter = await canonicalPath(descriptor.filePath, 'trusted converter'); }
  catch (error) { return { schema:LOCATION_SCHEMA, ok:false, code:'CONVERTER_LOCATION_GAP', detail:error.message }; }

  const checkedRoots = [];
  let candidates;
  try { candidates = normalizedRoots(roots); }
  catch (error) { return { schema:LOCATION_SCHEMA, ok:false, code:'CONVERTER_LOCATION_GAP', detail:`受保护根路径非法: ${error?.message || String(error)}` }; }

  for (const candidate of candidates) {
    let canonical;
    try { canonical = await canonicalPath(candidate.path, candidate.label); }
    catch (error) { return { schema:LOCATION_SCHEMA, ok:false, code:'CONVERTER_LOCATION_GAP', detail:error.message, converterRealPath:converter.realPath }; }
    const row = { label:candidate.label, path:candidate.path, realPath:canonical.realPath };
    checkedRoots.push(row);
    if (containsPath(canonical.realPath, converter.realPath)) {
      return {
        schema:LOCATION_SCHEMA,
        ok:false,
        code:'CONVERTER_LOCATION_GAP',
        detail:`trusted converter 位于受保护 ${candidate.label} 内；请使用赛题目录之外预先安装并审计的 optimum-cli`,
        converterPath:converter.input,
        converterRealPath:converter.realPath,
        forbiddenRoot:row,
        checkedRoots
      };
    }
  }

  return {
    schema:LOCATION_SCHEMA,
    ok:true,
    converterPath:converter.input,
    converterRealPath:converter.realPath,
    checkedRoots
  };
}

module.exports = {
  LOCATION_SCHEMA,
  containsPath,
  normalizedRoots,
  validateTrustedConverterLocation
};
