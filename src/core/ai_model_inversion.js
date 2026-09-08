function vector(value) {
  if (Array.isArray(value)) return value.map(Number).filter(Number.isFinite);
  if (value && typeof value==='object') {
    const vals=Object.values(value).map(Number);
    return vals.length&&vals.every(Number.isFinite)?vals:[];
  }
  const text=String(value??'').trim();
  if (!text) return [];
  try { return vector(JSON.parse(text)); } catch {}
  return text.split(/[|,;\s]+/).map(Number).filter(Number.isFinite);
}

function cosine(a,b) {
  if (!a.length||a.length!==b.length) return null;
  let dot=0,aa=0,bb=0;
  for (let i=0;i<a.length;i+=1) { dot+=a[i]*b[i]; aa+=a[i]*a[i]; bb+=b[i]*b[i]; }
  return aa>0&&bb>0?dot/Math.sqrt(aa*bb):null;
}

function distanceMetrics(reference,reconstructed) {
  const a=vector(reference), b=vector(reconstructed);
  if (!a.length||a.length!==b.length) return null;
  let l1=0,l2=0,linf=0;
  for (let i=0;i<a.length;i+=1) {
    const d=Math.abs(a[i]-b[i]); l1+=d; l2+=d*d; linf=Math.max(linf,d);
  }
  return { dimensions:a.length, mae:l1/a.length, l1, l2:Math.sqrt(l2), linf, cosine:cosine(a,b) };
}

function parseRows(input) {
  if (Array.isArray(input)) return input;
  if (input&&typeof input==='object') return Array.isArray(input.rows)?input.rows:[input];
  const text=String(input||'').trim();
  if (!text) throw new Error('请输入模型输出 transcript 或 reference/reconstructed JSON');
  if (/^[\[{]/.test(text)) {
    const parsed=JSON.parse(text);
    return Array.isArray(parsed)?parsed:Array.isArray(parsed.rows)?parsed.rows:[parsed];
  }
  const lines=text.split(/\r?\n/).filter(Boolean);
  const headers=(lines.shift()||'').split(',').map((x)=>x.trim());
  return lines.map((line)=>{ const vals=line.split(','); const row={}; headers.forEach((h,i)=>row[h]=vals[i]??''); return row; });
}

function analyzeModelInversion(input) {
  const rows=parseRows(input);
  const reconstructions=[];
  let probabilityVectors=0; let logitVectors=0; let embeddingVectors=0; let gradientRows=0; let featureRows=0;
  const findings=[];

  for (let i=0;i<rows.length;i+=1) {
    const row=rows[i]||{};
    const probs=vector(row.probabilities??row.probs??row.probability_vector);
    const logits=vector(row.logits??row.scores);
    const embedding=vector(row.embedding??row.hidden_state??row.features);
    const gradient=vector(row.gradient??row.gradients);
    if (probs.length>1) probabilityVectors+=1;
    if (logits.length>1) logitVectors+=1;
    if (embedding.length>1) embeddingVectors+=1;
    if (gradient.length>1) gradientRows+=1;
    if (vector(row.input_features??row.feature_vector).length>1) featureRows+=1;
    const reference=row.reference??row.original??row.target;
    const reconstructed=row.reconstructed??row.reconstruction??row.inverted;
    if (reference!=null&&reconstructed!=null) {
      const metrics=distanceMetrics(reference,reconstructed);
      if (metrics) reconstructions.push({ row:i+1, ...metrics });
    }
  }

  const total=Math.max(rows.length,1);
  if (gradientRows/total>=0.25) findings.push({
    id:'inversion-gradient-exposure',severity:'high',title:'API/日志暴露梯度向量',evidence:`gradientRows=${gradientRows}/${rows.length}`,
    meaning:'梯度通常比 top-1/概率输出包含更多关于输入与训练样本的局部信息；需确认是否属于调试接口或赛题特意暴露。'
  });
  if (embeddingVectors/total>=0.5) findings.push({
    id:'inversion-embedding-exposure',severity:'high',title:'大量暴露 embedding/hidden-state',evidence:`embeddingRows=${embeddingVectors}/${rows.length}`,
    meaning:'中间表示可能支持属性推断、近邻恢复或输入重建；业务不需要时不应直接返回。'
  });
  if (logitVectors/total>=0.5) findings.push({
    id:'inversion-logit-exposure',severity:'medium',title:'大量暴露完整 logit/score 向量',evidence:`logitRows=${logitVectors}/${rows.length}`,
    meaning:'完整 logits 同时增加模型抽取和反演类攻击的信息量；应按最小输出原则收敛。'
  });
  if (probabilityVectors/total>=0.5) findings.push({
    id:'inversion-probability-exposure',severity:'medium',title:'大量暴露完整概率分布',evidence:`probabilityRows=${probabilityVectors}/${rows.length}`,
    meaning:'完整概率分布可作为反演优化目标，比仅返回标签更容易估计目标类别输入特征。'
  });

  const strongRecon=reconstructions.filter((x)=>Number.isFinite(x.cosine)&&x.cosine>=0.95&&x.mae<=0.05);
  if (strongRecon.length) findings.push({
    id:'inversion-reconstruction-similarity',severity:'high',title:'重建样本与 reference 高度相似',evidence:strongRecon.slice(0,12),
    meaning:'当前候选在数值空间上与 reference 高度一致；若 reference 确实代表受保护输入，应继续用独立感知/任务指标确认隐私影响。'
  });

  let exposureScore=0;
  exposureScore+=gradientRows?4:0;
  exposureScore+=embeddingVectors/total>=0.5?4:0;
  exposureScore+=logitVectors/total>=0.5?2:0;
  exposureScore+=probabilityVectors/total>=0.5?1:0;
  exposureScore+=strongRecon.length?4:0;
  const privacyExposure=exposureScore>=7?'high':exposureScore>=4?'medium':exposureScore>=1?'low':'limited';

  const nextActions=[];
  if (gradientRows||embeddingVectors) nextActions.push('先确认这些向量是否真的跨越了 API/租户边界，而不是仅存在于本地调试日志。');
  if (probabilityVectors||logitVectors) nextActions.push('用固定 preprocessing 和独立 query 集评估“仅标签 / top-k / 完整向量”三种输出对重建质量的差异。');
  if (reconstructions.length) nextActions.push('不要只看视觉主观相似；同时报告 MAE/L2/L∞/cosine，并在适用时补 SSIM/PSNR 或任务级识别率。');

  return {
    rows:rows.length,
    probabilityVectors,
    logitVectors,
    embeddingVectors,
    gradientRows,
    featureRows,
    reconstructionPairs:reconstructions.length,
    reconstructions:reconstructions.slice(0,200),
    privacyExposure,
    findings,
    nextActions,
    notes:['Model inversion 与 membership inference 不同：这里关注从模型输出/梯度/中间表示恢复输入特征或代表性样本。','高相似 reconstruction 仍需确认 reference 的隐私语义和真实 API 可达性。']
  };
}

module.exports={ vector, cosine, distanceMetrics, analyzeModelInversion };
