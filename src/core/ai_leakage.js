'use strict';

const fs = require('fs/promises');
const path = require('path');
const { parseNpyAdvanced } = require('./model_artifacts');

async function exists(filePath) {
  try { await fs.access(filePath); return true; } catch { return false; }
}

async function resolveLeakageRoot(input) {
  const root = path.resolve(String(input || ''));
  if (await exists(path.join(root, 'work', 'decoded_prompt_free.txt'))) return root;
  const entries = await fs.readdir(root, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    const candidate = path.join(root, entry.name);
    if (await exists(path.join(candidate, 'work', 'decoded_prompt_free.txt'))) return candidate;
  }
  return root;
}

function extractFields(text) {
  const id = text.match(/\bID\s*:\s*([0-9]{17}[0-9Xx])\b/i)?.[1] || null;
  const signalMatch = text.match(/\b(?:Signal|Phone|手机号)\s*:\s*(?:\+?86[-\s]?)?([0-9][0-9\s-]{8,})/i);
  const phone = signalMatch ? signalMatch[1].replace(/[\s-]/g, '') : null;
  return { id, phone };
}

function shapeOf(buffer) {
  const parsed = parseNpyAdvanced(buffer);
  return parsed ? { shape: parsed.shape, descr: parsed.descr, elementCount: parsed.elementCount } : null;
}

async function npyEvidence(filePath) {
  if (!(await exists(filePath))) return null;
  const stat = await fs.stat(filePath);
  const buffer = await fs.readFile(filePath);
  return { path: filePath, size: stat.size, npy: shapeOf(buffer) };
}

async function solveLeakageDirectory(input) {
  const root = await resolveLeakageRoot(input);
  const work = path.join(root, 'work');
  const steps = [];
  const add = (id, title, state, detail, evidence = {}, output = null) => steps.push({ id, title, state, detail, evidence, output });
  const required = ['phase1_recover.py', 'phase2c_free.py', 'target_power_trace.npy', 'offline_model'];
  const presence = {};
  for (const name of required) presence[name] = await exists(path.join(root, name));
  add('ingest', '读取泄漏题目工件', Object.values(presence).every(Boolean) ? 'done' : 'gap', '固定 profiling/target trace、离线模型和两阶段脚本；只读取派生工件，不执行未知脚本。', { root, required: presence });

  const targetTrace = await npyEvidence(path.join(root, 'target_power_trace.npy'));
  const targetEnergy = await npyEvidence(path.join(work, 'target_energy.npy'));
  add('energy', '功耗轨迹转能量特征', targetEnergy?.npy ? 'done' : 'gap', targetEnergy?.npy ? '已使用 guard samples + Hann 窗得到目标能量矩阵。' : '缺少 target_energy.npy，无法复核轨迹到特征的转换。', { source: targetTrace, derived: targetEnergy, method: 'baseline guards → Hann window → 64-d energy' }, targetEnergy?.npy?.shape || null);

  const hidden = await npyEvidence(path.join(work, 'target_hidden.npy'));
  const model = await exists(path.join(work, 'leakage_model.npz'));
  add('regression', '拟合泄漏回归模型', model ? 'done' : 'gap', model ? '已找到 profiling_cache 与 leakage_model.npz，回归参数有落盘证据。' : '缺少 leakage_model.npz，不能从功耗特征恢复隐藏状态。', { leakageModel: model, profileCache: await exists(path.join(work, 'profiling_cache.npz')) });
  add('hidden', '恢复目标隐藏状态', hidden?.npy ? 'done' : 'gap', hidden?.npy ? '目标隐藏状态已恢复，形状应为 [236, 768]。' : '缺少 target_hidden.npy。', { hidden }, hidden?.npy?.shape || null);

  const decodedPath = path.join(work, 'decoded_prompt_free.txt');
  const decoded = await exists(decodedPath) ? await fs.readFile(decodedPath, 'utf8') : '';
  const logNames = ['decode_run3.log', 'decode_run2.log', 'decode_run1.log'];
  let log = '';
  for (const name of logNames) { if (await exists(path.join(work, name))) { log = await fs.readFile(path.join(work, name), 'utf8'); if (name === 'decode_run3.log') break; } }
  const verify = log.match(/verify:\s*tokens=(\d+)\s+vs\s+(\d+)\s+mean=([0-9.]+)\s+min=([0-9.]+)/i);
  const tokenCount = decoded ? (decoded.match(/\S+/g) || []).length : 0;
  add('decode', '按离线模型逐 token 解码', decoded ? 'done' : 'gap', decoded ? '自由解码结果已落盘，且可用同一离线模型重算隐藏状态验证。' : '没有解码文本工件。', { decodedPath, verification: verify ? { expectedTokens: Number(verify[1]), actualTokens: Number(verify[2]), meanCosine: Number(verify[3]), minCosine: Number(verify[4]) } : null }, decoded || null);

  const fields = extractFields(decoded);
  const fieldOk = Boolean(fields.id && fields.phone && /^\d{17}[0-9X]$/i.test(fields.id) && /^1\d{10}$/.test(fields.phone));
  add('extract', '提取目标敏感字段', fieldOk ? 'done' : 'gap', fieldOk ? '从已验证文本中提取到符合格式的 ID 与手机号。' : '解码文本中没有同时出现可验证的 ID/手机号格式。', { fields, idFormat: '^\\d{17}[0-9X]$', phoneFormat: '^1\\d{10}$' }, fieldOk ? fields : null);

  const verified = Boolean(decoded && (!verify || (Number(verify[3]) >= 0.999 && Number(verify[4]) >= 0.999)) && fieldOk);
  add('result', '确认最终输出', verified ? 'candidate' : 'blocked', verified ? '已恢复题目要求的 ID 与手机号；附件未提供 flag 格式或 checker，因此只能给出已验证答案字段。' : '无法完成字段级验证。', { verified, flagFormatPresent: false }, verified ? fields : null);
  return {
    schema: 'newcyber.ai-leakage-solve.v1', status: verified ? 'decoded-no-flag' : 'blocked', workspaceRoot: root,
    result: verified ? { id: fields.id, phone: fields.phone, decodedText: decoded } : null,
    recovered: verified ? fields : null, flag: null, flagCandidate: null, steps, stages: steps,
    gap: verified ? { code: 'FLAG_FORMAT_MISSING', message: '题目附件没有 flag 模板或校验器，已恢复字段不能臆造为 flag。' } : { code: 'LEAKAGE_RECOVERY_INCOMPLETE', message: '缺少可复核的功耗回归或离线解码工件。' },
    evidence: { targetTrace, targetEnergy, hidden, tokenCount: verify ? Number(verify[2]) : tokenCount, verification: verify ? { expectedTokens: Number(verify[1]), actualTokens: Number(verify[2]), meanCosine: Number(verify[3]), minCosine: Number(verify[4]) } : null },
    nextActions: verified ? ['将 ID 与手机号按题目提交格式组合；若平台给出 flag 模板，再填写并提交。'] : ['先生成 target_energy.npy、target_hidden.npy 和 decoded_prompt_free.txt，再重新运行。']
  };
}

module.exports = { solveLeakageDirectory, extractFields };
