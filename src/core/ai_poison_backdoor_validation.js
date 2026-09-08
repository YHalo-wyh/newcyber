const { parseDataset } = require('./ai_dataset_security');

function toNumber(value) {
  if (value===null || value===undefined || value==='') return null;
  const n=Number(value);
  return Number.isFinite(n) ? n : null;
}

function toBool(value) {
  if (typeof value==='boolean') return value;
  if (typeof value==='number') return value!==0;
  const text=String(value??'').trim().toLowerCase();
  if (['1','true','yes','y','poison','poisoned','triggered'].includes(text)) return true;
  if (['0','false','no','n','clean'].includes(text)) return false;
  return null;
}

function firstValue(row, names) {
  for (const name of names) if (Object.prototype.hasOwnProperty.call(row,name) && row[name]!=='' && row[name]!==null && row[name]!==undefined) return row[name];
  const byLower=new Map(Object.keys(row).map((k)=>[k.toLowerCase(),k]));
  for (const name of names) {
    const key=byLower.get(name.toLowerCase());
    if (key && row[key]!=='' && row[key]!==null && row[key]!==undefined) return row[key];
  }
  return null;
}

function stable(value) {
  if (value===null || value===undefined) return null;
  return String(value).trim();
}

function parseObjectOrRows(input) {
  if (input && typeof input==='object' && !Array.isArray(input)) {
    if (Array.isArray(input.rows)) return { meta:input, rows:input.rows.slice(0,50000) };
    return { meta:input, rows:[] };
  }
  if (Array.isArray(input)) return { meta:{}, rows:input.slice(0,50000) };
  const text=String(input||'').trim();
  if (!text) throw new Error('请输入 CSV/TSV 或 JSON');
  if (/^[\[{]/.test(text)) {
    const parsed=JSON.parse(text);
    if (Array.isArray(parsed)) return { meta:{}, rows:parsed.slice(0,50000) };
    return { meta:parsed, rows:Array.isArray(parsed.rows)?parsed.rows.slice(0,50000):[] };
  }
  const parsed=parseDataset(text);
  return { meta:{}, rows:parsed.rows.slice(0,50000) };
}

function metricObject(value) {
  if (!value || typeof value!=='object' || Array.isArray(value)) return {};
  const out={};
  for (const [key,raw] of Object.entries(value)) {
    const n=toNumber(raw);
    if (n!==null) out[key]=n;
  }
  return out;
}

function deltas(baseline,suspect) {
  const keys=[...new Set([...Object.keys(baseline),...Object.keys(suspect)])];
  const out={};
  for (const key of keys) {
    if (baseline[key]===undefined || suspect[key]===undefined) continue;
    out[key]=suspect[key]-baseline[key];
  }
  return out;
}

function analyzePoisoningImpact(input) {
  const { meta,rows }=parseObjectOrRows(input);
  const findings=[];
  let poisonMarked=0;
  let cleanMarked=0;
  let poisonUnknown=0;
  let labelComparable=0;
  let labelFlips=0;
  const targetCounts={};
  const triggerCounts={};
  const poisonRows=[];

  for (let index=0; index<rows.length; index++) {
    const row=rows[index];
    const marker=toBool(firstValue(row,['is_poison','poisoned','is_poisoned','poison','split']));
    if (marker===true) poisonMarked++;
    else if (marker===false) cleanMarked++;
    else poisonUnknown++;
    if (marker!==true) continue;

    const observed=stable(firstValue(row,['label','target','class','y']));
    const original=stable(firstValue(row,['original_label','clean_label','source_label','before_label']));
    const target=stable(firstValue(row,['target_label','attack_target','poison_target']));
    const trigger=stable(firstValue(row,['trigger_id','trigger','pattern','patch_id']));
    if (observed!==null && original!==null) {
      labelComparable++;
      if (observed!==original) labelFlips++;
    }
    const effectiveTarget=target??observed;
    if (effectiveTarget!==null) targetCounts[effectiveTarget]=(targetCounts[effectiveTarget]||0)+1;
    if (trigger!==null) triggerCounts[trigger]=(triggerCounts[trigger]||0)+1;
    if (poisonRows.length<100) poisonRows.push({ row:row.__row??index+1, originalLabel:original, label:observed, targetLabel:target, trigger });
  }

  const totalKnown=poisonMarked+cleanMarked;
  const contaminationRate=totalKnown ? poisonMarked/totalKnown : null;
  const labelFlipRate=labelComparable ? labelFlips/labelComparable : null;
  const targetTop=Object.entries(targetCounts).sort((a,b)=>b[1]-a[1])[0]||null;
  const targetConcentration=targetTop && poisonMarked ? targetTop[1]/poisonMarked : null;
  const triggerTop=Object.entries(triggerCounts).sort((a,b)=>b[1]-a[1])[0]||null;

  const baseline=metricObject(meta.baseline||meta.cleanModel||meta.clean_metrics);
  const suspect=metricObject(meta.suspect||meta.poisonedModel||meta.poisoned_metrics);
  const impact=deltas(baseline,suspect);
  const triggered=metricObject(meta.triggered||meta.triggeredMetrics||meta.attack_metrics);

  if (poisonMarked && contaminationRate!==null) findings.push({
    id:'poisoning-explicit-contamination',severity:contaminationRate>=0.05?'medium':'info',title:'存在显式标记的污染样本',
    evidence:`poison=${poisonMarked}/${totalKnown}, rate=${contaminationRate.toFixed(4)}`,
    meaning:'输入中存在显式 poison 标记，可用于建立干净/可疑子集。污染比例本身不证明攻击成功，应继续看标签变化、目标集中度和模型影响。'
  });
  if (labelFlipRate!==null && labelFlipRate>=0.2) findings.push({
    id:'poisoning-label-flip-candidate',severity:labelFlipRate>=0.8?'high':'medium',title:'污染样本存在集中标签翻转',
    evidence:`label_flips=${labelFlips}/${labelComparable}, rate=${labelFlipRate.toFixed(4)}`,
    meaning:'大量显式污染样本的观察标签与原始标签不同，符合 label-flip poisoning 的候选形态；需结合来源、任务规则和对照训练确认。'
  });
  if (targetConcentration!==null && poisonMarked>=3 && targetConcentration>=0.75) findings.push({
    id:'poisoning-target-concentration',severity:'medium',title:'污染样本向单一目标标签集中',
    evidence:`target=${targetTop[0]}, support=${targetTop[1]}, concentration=${targetConcentration.toFixed(4)}`,
    meaning:'污染样本高度集中到单一标签，可能是定向投毒或后门目标标签候选；合法类不平衡也可能产生类似分布。'
  });

  const accuracyDelta=impact.accuracy??impact.acc??null;
  const f1Delta=impact.f1??impact.f1_score??null;
  const lossDelta=impact.loss??null;
  if ((accuracyDelta!==null && accuracyDelta<=-0.05) || (f1Delta!==null && f1Delta<=-0.05) || (lossDelta!==null && lossDelta>=0.1)) findings.push({
    id:'poisoning-model-impact-candidate',severity:'medium',title:'可疑训练集对应模型性能出现退化',
    evidence:JSON.stringify({accuracyDelta,f1Delta,lossDelta}),
    meaning:'baseline 与 suspect 指标出现明显退化，说明数据变化可能已经影响模型行为；但训练随机性、数据切分和超参数差异必须作为对照变量排除。'
  });

  return {
    rows:rows.length,
    marked:{ poison:poisonMarked,clean:cleanMarked,unknown:poisonUnknown },
    contaminationRate,
    labelFlip:{ comparable:labelComparable,flips:labelFlips,rate:labelFlipRate },
    targetDistribution:targetCounts,
    targetConcentration:targetTop?{ label:targetTop[0],support:targetTop[1],ratio:targetConcentration }:null,
    triggerDistribution:triggerCounts,
    topTrigger:triggerTop?{ trigger:triggerTop[0],support:triggerTop[1] }:null,
    metrics:{ baseline,suspect,deltas:impact,triggered },
    poisonRows,
    findings,
    verdict:findings.some((x)=>x.severity==='high')?'strong-candidate':findings.length?'candidate':'insufficient-evidence',
    nextActions:[
      '固定同一训练配置和随机种子，分别在 clean / suspect 数据上训练或复评，避免把超参数差异误判成投毒影响。',
      '对可疑样本做 provenance、标签来源、重复/近重复和 trigger 共现复核；优先验证“移除可疑子集后指标是否恢复”。',
      '若存在目标标签或 trigger，再交给后门行为验证器比较 clean 与 triggered 输入的预测迁移。'
    ],
    notes:['本模块只做授权环境中的防御性证据评估，不生成用于真实系统的数据投毒载荷。','没有显式 poison 标记时，优先使用“数据投毒 / 后门排查”模块从冲突标签与异常 trigger 共现中找候选。']
  };
}

function chooseGlobalTarget(meta,rows) {
  const explicit=stable(meta.targetLabel??meta.target_label??meta.attackTarget??meta.attack_target);
  if (explicit!==null) return explicit;
  const counts={};
  for (const row of rows) {
    const value=stable(firstValue(row,['target_label','attack_target','backdoor_target']));
    if (value!==null) counts[value]=(counts[value]||0)+1;
  }
  return Object.entries(counts).sort((a,b)=>b[1]-a[1])[0]?.[0]??null;
}

function analyzeBackdoorBehavior(input) {
  const { meta,rows }=parseObjectOrRows(input);
  if (!rows.length) throw new Error('后门行为验证需要 rows 或 CSV：至少包含 clean_pred 与 triggered_pred；最好包含 true_label 和 target_label。');
  const targetLabel=chooseGlobalTarget(meta,rows);
  const findings=[];
  let paired=0, flips=0;
  let cleanTruth=0,cleanCorrect=0,triggerTruth=0,triggerCorrect=0;
  let eligibleTarget=0,targetHits=0;
  let controlPaired=0,controlTargetHits=0;
  const transitions={};
  const examples=[];

  for (let index=0; index<rows.length; index++) {
    const row=rows[index];
    const truth=stable(firstValue(row,['true_label','label','y_true','ground_truth']));
    const clean=stable(firstValue(row,['clean_pred','original_pred','pred_clean','baseline_pred']));
    const triggered=stable(firstValue(row,['triggered_pred','trigger_pred','pred_triggered','backdoor_pred']));
    const control=stable(firstValue(row,['control_pred','neutral_pred','sham_pred']));
    if (clean!==null && triggered!==null) {
      paired++;
      if (clean!==triggered) flips++;
      const key=`${clean}→${triggered}`;
      transitions[key]=(transitions[key]||0)+1;
    }
    if (truth!==null && clean!==null) { cleanTruth++; if (truth===clean) cleanCorrect++; }
    if (truth!==null && triggered!==null) { triggerTruth++; if (truth===triggered) triggerCorrect++; }
    if (targetLabel!==null && triggered!==null && truth!==targetLabel) {
      eligibleTarget++;
      if (triggered===targetLabel) targetHits++;
      if (control!==null) { controlPaired++; if (control===targetLabel) controlTargetHits++; }
    }
    if (examples.length<100 && clean!==null && triggered!==null && clean!==triggered) examples.push({row:row.__row??index+1,trueLabel:truth,cleanPred:clean,triggeredPred:triggered,controlPred:control});
  }

  const cleanAccuracy=cleanTruth?cleanCorrect/cleanTruth:null;
  const triggeredAccuracy=triggerTruth?triggerCorrect/triggerTruth:null;
  const accuracyDrop=cleanAccuracy!==null&&triggeredAccuracy!==null?cleanAccuracy-triggeredAccuracy:null;
  const flipRate=paired?flips/paired:null;
  const targetASR=eligibleTarget?targetHits/eligibleTarget:null;
  const controlTargetRate=controlPaired?controlTargetHits/controlPaired:null;
  const triggerSpecificity=targetASR!==null&&controlTargetRate!==null?targetASR-controlTargetRate:null;
  const topTransition=Object.entries(transitions).sort((a,b)=>b[1]-a[1])[0]||null;
  const transitionConcentration=topTransition&&paired?topTransition[1]/paired:null;

  if (targetASR!==null && eligibleTarget>=5 && targetASR>=0.8 && (cleanAccuracy===null || cleanAccuracy>=0.6)) findings.push({
    id:'backdoor-target-asr-candidate',severity:'high',title:'Triggered 输入高度集中到目标标签',
    evidence:`target=${targetLabel}, asr=${targetASR.toFixed(4)}, eligible=${eligibleTarget}, clean_acc=${cleanAccuracy===null?'n/a':cleanAccuracy.toFixed(4)}`,
    meaning:'在非目标类样本上，triggered 输入被大量映射到同一目标标签，同时 clean 行为未完全失效，符合目标型后门的强候选行为。仍需用中性 patch/位置变化/随机纹理等对照排除普通分布外敏感性。'
  });
  if (flipRate!==null && paired>=5 && flipRate>=0.5) findings.push({
    id:'backdoor-trigger-flip-candidate',severity:'medium',title:'Trigger 前后预测翻转率较高',
    evidence:`flips=${flips}/${paired}, rate=${flipRate.toFixed(4)}`,
    meaning:'同一批样本在 clean 与 triggered 条件下频繁改变预测；这是后门/触发敏感性的候选证据，不足以单独证明存在后门。'
  });
  if (transitionConcentration!==null && paired>=5 && transitionConcentration>=0.5 && topTransition[0].split('→')[0]!==topTransition[0].split('→')[1]) findings.push({
    id:'backdoor-transition-concentration',severity:'medium',title:'预测迁移集中到固定方向',
    evidence:`transition=${topTransition[0]}, support=${topTransition[1]}, concentration=${transitionConcentration.toFixed(4)}`,
    meaning:'触发前后的标签迁移高度集中，优先检查该目标标签是否与数据集中的可疑 trigger 共现。'
  });
  if (triggerSpecificity!==null && controlPaired>=5 && triggerSpecificity>=0.5) findings.push({
    id:'backdoor-control-specificity',severity:'high',title:'Trigger 效应明显高于中性对照',
    evidence:`trigger_target_rate=${targetASR.toFixed(4)}, control_target_rate=${controlTargetRate.toFixed(4)}, delta=${triggerSpecificity.toFixed(4)}`,
    meaning:'同一目标标签在真实 trigger 条件下的命中率显著高于中性对照，是比“只看 ASR”更强的特异性证据。'
  });

  return {
    rows:rows.length,
    targetLabel,
    paired,
    metrics:{
      cleanAccuracy,triggeredAccuracy,accuracyDrop,flipRate,targetASR,controlTargetRate,triggerSpecificity
    },
    transitions,
    topTransition:topTransition?{ transition:topTransition[0],support:topTransition[1],ratio:transitionConcentration }:null,
    examples,
    findings,
    verdict:findings.some((x)=>x.severity==='high')?'strong-candidate':findings.length?'candidate':'insufficient-evidence',
    nextActions:[
      '用同一批样本保持除 trigger 外其他像素/特征不变，比较 clean → triggered 的预测迁移。',
      '加入随机 patch、相同大小不同纹理、位置平移或 trigger-removal 作为 control，验证效应是否对特定 trigger 具有特异性。',
      '同时报告 Clean Accuracy、Triggered Accuracy、Target ASR、Flip Rate 和 Control Target Rate，避免只用单一 ASR 下结论。',
      '将行为侧 target/trigger 与数据集侧 trigger 候选、模型结构异常和训练 provenance 交叉验证后，再升级为确认问题。'
    ],
    notes:['该验证器用于检测/复核后门行为，不提供后门植入或真实系统攻击代码。','高 ASR 可能来自自然 shortcut、OOD 敏感性或错误预处理；control ablation 是必要证据。']
  };
}

module.exports={ analyzePoisoningImpact, analyzeBackdoorBehavior };
