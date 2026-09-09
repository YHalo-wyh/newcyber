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

function normalizeBatchSamples(data) {
  if (Array.isArray(data.samples) && data.samples.length) return data.samples;
  const originals=data.original ?? data.clean ?? data.x;
  const adversarials=data.adversarial ?? data.adv ?? data.x_adv ?? data.xAdv;
  if (!Array.isArray(originals)||!Array.isArray(adversarials)||!Array.isArray(originals[0])||!Array.isArray(adversarials[0])) throw new Error('批量模式需要 samples[]，或二维 original/adversarial 数组');
  if (originals.length!==adversarials.length) throw new Error('批量 original/adversarial 行数不一致');
  const labels=data.trueLabels ?? data.labels ?? [];
  const targets=data.targetLabels ?? [];
  const originalPreds=data.predictedOriginal ?? data.originalPredictions ?? [];
  const adversarialPreds=data.predictedAdversarial ?? data.adversarialPredictions ?? [];
  return originals.map((original,index)=>({
    original,adversarial:adversarials[index],
    trueLabel:Array.isArray(labels)?labels[index]:data.trueLabel,
    targetLabel:Array.isArray(targets)?targets[index]:data.targetLabel,
    predictedOriginal:Array.isArray(originalPreds)?originalPreds[index]:null,
    predictedAdversarial:Array.isArray(adversarialPreds)?adversarialPreds[index]:null
  }));
}

function analyzeAdversarialBatch(input) {
  const data=parseInput(input);
  const samples=normalizeBatchSamples(data);
  if (!samples.length) throw new Error('批量对抗样本为空');
  if (samples.length>100000) throw new Error('批量对抗样本超过 100000 行上限');
  const defaults={norm:data.norm||'linf',epsilon:data.epsilon??data.eps,clip:data.clip,clipMin:data.clipMin,clipMax:data.clipMax,targetLabel:data.targetLabel};
  const results=samples.map((sample,index)=>({index,result:analyzeAdversarialPair({...defaults,...sample})}));
  const budgetKnown=results.filter((x)=>x.result.withinBudget!==null);
  const within=budgetKnown.filter((x)=>x.result.withinBudget===true);
  const over=budgetKnown.filter((x)=>x.result.withinBudget===false);
  const evaluated=results.filter((x)=>x.result.outcome.success!==null);
  const validEvaluated=evaluated.filter((x)=>x.result.withinBudget!==false);
  const successful=validEvaluated.filter((x)=>x.result.withinBudget===true&&x.result.outcome.success===true);
  const trueLabelRows=results.filter((x)=>x.result.outcome.trueLabel!=null&&x.result.outcome.adversarialPrediction!=null);
  const advCorrect=trueLabelRows.filter((x)=>String(x.result.outcome.trueLabel)===String(x.result.outcome.adversarialPrediction)).length;
  const cleanRows=results.filter((x)=>x.result.outcome.trueLabel!=null&&x.result.outcome.originalPrediction!=null);
  const cleanCorrect=cleanRows.filter((x)=>String(x.result.outcome.trueLabel)===String(x.result.outcome.originalPrediction)).length;
  const normValues=results.map((x)=>x.result.selectedNormValue).filter(Number.isFinite);
  const findings=[];
  if (over.length) findings.push({id:'adversarial-batch-budget-violations',severity:'high',evidence:`${over.length}/${results.length} samples exceed budget`,meaning:'比赛提交中存在超预算样本；整批结果不能直接视为有效攻击集。'});
  if (successful.length) findings.push({id:'adversarial-batch-success',severity:'high',evidence:`${successful.length}/${results.length} within-budget successful attacks`,meaning:'整批样本中存在满足预算且达到目标的对抗样本；可按赛题 scorer 继续看整体成功率/鲁棒准确率。'});
  return {
    schema:'newcyber.ai-adversarial-batch.v1',
    samples:results.length,
    norm:results[0].result.norm,
    epsilon:results[0].result.epsilon,
    budget:{known:budgetKnown.length,within:within.length,over:over.length,passRate:budgetKnown.length?within.length/budgetKnown.length:null,allWithin:budgetKnown.length===results.length&&over.length===0},
    attack:{evaluated:evaluated.length,validEvaluated:validEvaluated.length,successful:successful.length,successRate:evaluated.length?successful.length/evaluated.length:null,validSuccessRate:validEvaluated.length?successful.length/validEvaluated.length:null},
    accuracy:{clean:cleanRows.length?cleanCorrect/cleanRows.length:null,adversarial:trueLabelRows.length?advCorrect/trueLabelRows.length:null},
    selectedNorm:{max:normValues.length?Math.max(...normValues):null,mean:normValues.length?normValues.reduce((a,b)=>a+b,0)/normValues.length:null},
    findings,
    rows:results.slice(0,512).map((x)=>({index:x.index,verdict:x.result.verdict,withinBudget:x.result.withinBudget,selectedNormValue:x.result.selectedNormValue,outcome:x.result.outcome})),
    notes:['批量 scorer 不执行模型；它只对题目已有预测结果和扰动数据做统一约束复算。','robust/adversarial accuracy 只有在 trueLabel 与 adversarial prediction 都给出时才计算。']
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

module.exports = { flattenFinite, computeNorms, analyzeAdversarialPair, analyzeAdversarialBatch, buildAdversarialHarness };
