function flattenFinite(value, out = []) {
  if (Array.isArray(value)) {
    for (const item of value) flattenFinite(item, out);
    return out;
  }
  const n = Number(value);
  if (!Number.isFinite(n)) throw new Error('样本中存在非有限数值');
  out.push(n);
  return out;
}

function parseInput(input) {
  if (input && typeof input === 'object') return input;
  const text = String(input || '').trim();
  if (!text) throw new Error('请输入 original / adversarial 样本');
  try { return JSON.parse(text); }
  catch { throw new Error('对抗样本审计输入应为 JSON'); }
}

function normalizeNorm(value) {
  const text = String(value || 'linf').toLowerCase().replace(/\s+/g, '');
  if (['linf','inf','l∞','infinity'].includes(text)) return 'linf';
  if (['l2','2'].includes(text)) return 'l2';
  if (['l1','1'].includes(text)) return 'l1';
  if (['l0','0'].includes(text)) return 'l0';
  return 'linf';
}

function computeNorms(original, adversarial) {
  if (original.length !== adversarial.length) throw new Error(`样本长度不一致：${original.length} vs ${adversarial.length}`);
  let l0 = 0; let l1 = 0; let l2sq = 0; let linf = 0;
  const changes = [];
  for (let i = 0; i < original.length; i += 1) {
    const delta = adversarial[i] - original[i];
    const abs = Math.abs(delta);
    if (abs > 1e-12) l0 += 1;
    l1 += abs;
    l2sq += delta * delta;
    linf = Math.max(linf, abs);
    if (abs > 0) changes.push({ index:i, original:original[i], adversarial:adversarial[i], delta, absDelta:abs });
  }
  changes.sort((a,b)=>b.absDelta-a.absDelta || a.index-b.index);
  return {
    l0,
    l1,
    l2: Math.sqrt(l2sq),
    linf,
    meanAbs: original.length ? l1 / original.length : 0,
    rms: original.length ? Math.sqrt(l2sq / original.length) : 0,
    changedRatio: original.length ? l0 / original.length : 0,
    topChanges: changes.slice(0, 24)
  };
}

function clipViolations(values, clip) {
  if (!Array.isArray(clip) || clip.length !== 2 || !clip.every(Number.isFinite)) return null;
  const [min,max] = clip;
  let below = 0; let above = 0;
  for (const value of values) {
    if (value < min) below += 1;
    if (value > max) above += 1;
  }
  return { min, max, below, above, total: below + above };
}

function inferScale(values) {
  if (!values.length) return 'unknown';
  const min = Math.min(...values.slice(0, 200000));
  const max = Math.max(...values.slice(0, 200000));
  if (min >= 0 && max <= 1.000001) return '0..1';
  if (min >= 0 && max <= 255.000001) return '0..255';
  if (min >= -5 && max <= 5) return 'normalized-like';
  return 'unbounded/unknown';
}

function attackOutcome(data) {
  const originalPrediction = data.predictedOriginal ?? data.originalPrediction ?? null;
  const adversarialPrediction = data.predictedAdversarial ?? data.adversarialPrediction ?? null;
  const trueLabel = data.trueLabel ?? data.label ?? null;
  const targetLabel = data.targetLabel ?? null;
  const changed = originalPrediction != null && adversarialPrediction != null
    ? String(originalPrediction) !== String(adversarialPrediction)
    : null;
  let success = null;
  let mode = 'unknown';
  if (targetLabel != null && adversarialPrediction != null) {
    mode = 'targeted';
    success = String(adversarialPrediction) === String(targetLabel);
  } else if (trueLabel != null && adversarialPrediction != null) {
    mode = 'untargeted';
    success = String(adversarialPrediction) !== String(trueLabel);
  } else if (changed != null) {
    mode = 'prediction-change';
    success = changed;
  }
  return { originalPrediction, adversarialPrediction, trueLabel, targetLabel, changed, success, mode };
}

function analyzeAdversarialPair(input) {
  const data = parseInput(input);
  const originalRaw = data.original ?? data.clean ?? data.x;
  const adversarialRaw = data.adversarial ?? data.adv ?? data.x_adv ?? data.xAdv;
  if (originalRaw == null || adversarialRaw == null) throw new Error('JSON 需要 original 与 adversarial（或 clean/x 与 adv/x_adv）');
  const original = flattenFinite(originalRaw);
  const adversarial = flattenFinite(adversarialRaw);
  if (!original.length) throw new Error('样本为空');

  const norms = computeNorms(original, adversarial);
  const norm = normalizeNorm(data.norm);
  const epsilon = Number(data.epsilon ?? data.eps);
  const selected = norms[norm];
  const withinBudget = Number.isFinite(epsilon) ? selected <= epsilon + 1e-12 : null;
  const clip = data.clip ?? (Number.isFinite(Number(data.clipMin)) && Number.isFinite(Number(data.clipMax)) ? [Number(data.clipMin), Number(data.clipMax)] : null);
  const clipping = clipViolations(adversarial, clip);
  const outcome = attackOutcome(data);

  let verdict = 'pair-only';
  if (withinBudget === false) verdict = 'over-budget';
  else if (withinBudget === true && outcome.success === true) verdict = 'within-budget-success';
  else if (withinBudget === true && outcome.success === false) verdict = 'within-budget-no-success';
  else if (withinBudget === true) verdict = 'within-budget-unverified';

  const findings = [];
  if (withinBudget === false) findings.push({ id:'adversarial-budget-exceeded', severity:'medium', evidence:`${norm}=${selected} > epsilon=${epsilon}`, meaning:'扰动超过题目给定预算；即使分类变化，也不能把它当有效对抗样本。' });
  if (withinBudget === true && outcome.success === true) findings.push({ id:'adversarial-candidate-valid', severity:'high', evidence:`${norm}=${selected} <= epsilon=${epsilon}; mode=${outcome.mode}`, meaning:'候选同时满足扰动预算与当前输出目标，可进入最终 verifier 复核。' });
  if (clipping?.total) findings.push({ id:'adversarial-clip-violation', severity:'medium', evidence:`below=${clipping.below} above=${clipping.above}`, meaning:'候选超出输入 clip 范围；应先按真实 preprocessing/clip 规则处理后重新评估。' });

  return {
    size: original.length,
    shape: Array.isArray(data.shape) ? data.shape : null,
    scale: inferScale(original),
    norm,
    epsilon: Number.isFinite(epsilon) ? epsilon : null,
    selectedNormValue: selected,
    withinBudget,
    norms,
    clipping,
    outcome,
    verdict,
    findings,
    notes:[
      '这里验证的是“扰动预算 + 已给出的模型输出/标签”，不是凭数值距离猜模型是否会误分类。',
      '若题目存在 resize/normalize/quantize 等 preprocessing，应在与 verifier 相同的数据空间计算预算。'
    ]
  };
}

function buildAdversarialHarness(input = {}) {
  const data = parseInput(input);
  const eps = Number.isFinite(Number(data.epsilon ?? data.eps)) ? Number(data.epsilon ?? data.eps) : 8/255;
  const clip = Array.isArray(data.clip) && data.clip.length===2 ? data.clip.map(Number) : [0,1];
  const attacks = Array.isArray(data.attacks) && data.attacks.length ? data.attacks : ['fgsm','pgd'];
  const art = `# NewCyber / ART harness\n# Fill only load_model_and_sample(); keep preprocessing identical to the challenge verifier.\nimport numpy as np\nfrom art.estimators.classification import PyTorchClassifier\nfrom art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent\n\ndef load_model_and_sample():\n    raise NotImplementedError('return model, loss_fn, optimizer, x_numpy, y_numpy, nb_classes, input_shape')\n\nmodel, loss_fn, optimizer, x, y, nb_classes, input_shape = load_model_and_sample()\nclassifier = PyTorchClassifier(model=model, loss=loss_fn, optimizer=optimizer, input_shape=input_shape, nb_classes=nb_classes, clip_values=(${clip[0]}, ${clip[1]}))\nattacks = []\n${attacks.includes('fgsm') ? `attacks.append(('fgsm', FastGradientMethod(estimator=classifier, eps=${eps})))` : ''}\n${attacks.includes('pgd') ? `attacks.append(('pgd', ProjectedGradientDescent(estimator=classifier, eps=${eps}, eps_step=${Math.max(eps/4,1e-6)}, max_iter=40)))` : ''}\nfor name, attack in attacks:\n    adv = attack.generate(x=x, y=y)\n    delta = adv - x\n    print(name, 'linf=', float(np.max(np.abs(delta))), 'pred=', classifier.predict(adv).argmax(axis=1).tolist())\n    np.save(f'newcyber_{name}_adv.npy', adv)\n`;

  const foolbox = `# NewCyber / Foolbox harness\n# Fill only load_model_and_sample(); sample tensor must already match verifier preprocessing.\nimport torch\nimport foolbox as fb\n\ndef load_model_and_sample():\n    raise NotImplementedError('return torch_model, x_tensor, y_tensor, bounds')\n\nmodel, x, y, bounds = load_model_and_sample()\nfmodel = fb.PyTorchModel(model.eval(), bounds=bounds)\nattack = fb.attacks.LinfPGD(steps=40)\nraw, clipped, success = attack(fmodel, x, y, epsilons=${eps})\nprint('success=', success.tolist())\nprint('linf=', float((clipped - x).abs().max()))\ntorch.save(clipped.detach().cpu(), 'newcyber_foolbox_adv.pt')\n`;

  return {
    epsilon:eps,
    clip,
    attacks,
    harnesses:[
      { backend:'ART', project:'Trusted-AI/adversarial-robustness-toolbox', script:art },
      { backend:'Foolbox', project:'bethgelab/foolbox', script:foolbox }
    ],
    notes:['脚本只负责把题目已有的可信模型 wrapper 接到成熟攻击库；模型加载方式与 preprocessing 必须按赛题实际代码补齐。']
  };
}

module.exports = { flattenFinite, computeNorms, analyzeAdversarialPair, buildAdversarialHarness };
