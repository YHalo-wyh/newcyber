function splitCsvLine(line, delimiter=',') {
  const out=[]; let cur=''; let quoted=false;
  for (let i=0;i<line.length;i+=1) {
    const c=line[i];
    if (c==='"') {
      if (quoted && line[i+1]==='"') { cur+='"'; i+=1; }
      else quoted=!quoted;
    } else if (c===delimiter && !quoted) { out.push(cur.trim()); cur=''; }
    else cur+=c;
  }
  out.push(cur.trim());
  return out;
}

function parseRows(input) {
  if (Array.isArray(input)) return input;
  if (input && typeof input==='object') return Array.isArray(input.rows) ? input.rows : [input];
  const text=String(input||'').trim();
  if (!text) throw new Error('请输入模型 API 查询 transcript（CSV/TSV/JSON）');
  if (/^[\[{]/.test(text)) {
    const parsed=JSON.parse(text);
    return Array.isArray(parsed) ? parsed : Array.isArray(parsed.rows) ? parsed.rows : [parsed];
  }
  const lines=text.split(/\r?\n/).filter((x)=>x.trim());
  if (lines.length<2) throw new Error('CSV/TSV 至少需要表头和一行数据');
  const delimiter=(lines[0].match(/\t/g)||[]).length>(lines[0].match(/,/g)||[]).length?'\t':',';
  const headers=splitCsvLine(lines[0],delimiter);
  return lines.slice(1).map((line)=>{
    const values=splitCsvLine(line,delimiter); const row={};
    headers.forEach((h,i)=>{ row[h]=values[i]??''; });
    return row;
  });
}

function pick(row, names) {
  for (const name of names) if (row[name]!==undefined && row[name]!==null && String(row[name]).trim()!=='') return row[name];
  return null;
}

function parseVector(value) {
  if (Array.isArray(value)) return value.map(Number).filter(Number.isFinite);
  if (value && typeof value==='object') {
    const vals=Object.values(value).map(Number);
    return vals.length && vals.every(Number.isFinite) ? vals : [];
  }
  const text=String(value??'').trim();
  if (!text) return [];
  try {
    const parsed=JSON.parse(text);
    if (Array.isArray(parsed)) return parsed.map(Number).filter(Number.isFinite);
    if (parsed && typeof parsed==='object') {
      const vals=Object.values(parsed).map(Number);
      return vals.length && vals.every(Number.isFinite) ? vals : [];
    }
  } catch {}
  const parts=text.split(/[|;\s]+/).map(Number).filter(Number.isFinite);
  return parts.length>1 ? parts : [];
}

function entropy(probabilities) {
  const sum=probabilities.reduce((a,b)=>a+b,0);
  if (!(sum>0)) return null;
  let out=0;
  for (const raw of probabilities) {
    const p=raw/sum;
    if (p>0) out-=p*Math.log2(p);
  }
  return out;
}

function decimalPrecision(value) {
  const text=String(value??'');
  const m=text.match(/\.(\d+)/);
  return m ? m[1].length : 0;
}

function stableString(value) {
  if (value==null) return '';
  if (typeof value==='string') return value.trim();
  try { return JSON.stringify(value); } catch { return String(value); }
}

function normalizeRow(row,index) {
  const query=pick(row,['query','input','text','image','sample','x','request','prompt','payload']) ?? `row:${index+1}`;
  const label=pick(row,['label','prediction','predicted_label','class','output','result','top1']);
  const vectorRaw=pick(row,['probabilities','probs','prob','scores','logits','confidence_vector','distribution']);
  const vector=parseVector(vectorRaw);
  const confidenceRaw=pick(row,['confidence','max_confidence','score','top1_confidence']);
  const confidence=Number(confidenceRaw);
  const latency=Number(pick(row,['latency_ms','latency','duration_ms','time_ms']));
  const vectorSum=vector.reduce((a,b)=>a+b,0);
  const probabilityLike=vector.length>1 && vector.every((x)=>x>=0 && x<=1) && Math.abs(vectorSum-1)<=0.03;
  return {
    index:index+1,
    query:stableString(query),
    label:label==null?null:stableString(label),
    vector,
    probabilityLike,
    confidence:Number.isFinite(confidence)?confidence:null,
    latencyMs:Number.isFinite(latency)?latency:null,
    raw:row
  };
}

function analyzeModelExtractionTranscript(input) {
  const rows=parseRows(input).map(normalizeRow);
  const queryMap=new Map();
  const labels={};
  let vectorRows=0; let probabilityRows=0; let fullPrecisionRows=0; let confidenceRows=0; let entropySum=0; let entropyCount=0;
  for (const row of rows) {
    const key=row.query;
    const list=queryMap.get(key)||[]; list.push(row); queryMap.set(key,list);
    if (row.label!=null) labels[row.label]=(labels[row.label]||0)+1;
    if (row.vector.length>1) {
      vectorRows+=1;
      if (row.probabilityLike) probabilityRows+=1;
      const values=pick(row.raw,['probabilities','probs','prob','scores','logits','confidence_vector','distribution']);
      const precision=Math.max(...String(values??'').split(/[^0-9.\-eE]+/).map(decimalPrecision),0);
      if (precision>=6) fullPrecisionRows+=1;
      const h=row.probabilityLike?entropy(row.vector):null;
      if (Number.isFinite(h)) { entropySum+=h; entropyCount+=1; }
    }
    if (row.confidence!=null) confidenceRows+=1;
  }

  let duplicateQueries=0; let inconsistentDuplicates=0; let deterministicDuplicates=0;
  for (const list of queryMap.values()) {
    if (list.length<2) continue;
    duplicateQueries+=1;
    const signatures=new Set(list.map((row)=>`${row.label??''}|${row.vector.length?row.vector.map((x)=>Number(x).toPrecision(12)).join(','):row.confidence??''}`));
    if (signatures.size>1) inconsistentDuplicates+=1;
    else deterministicDuplicates+=1;
  }

  const classCount=Object.keys(labels).length;
  const uniqueQueries=queryMap.size;
  const vectorRatio=rows.length?vectorRows/rows.length:0;
  const probabilityRatio=rows.length?probabilityRows/rows.length:0;
  const precisionRatio=rows.length?fullPrecisionRows/rows.length:0;
  const findings=[];

  if (probabilityRatio>=0.5) findings.push({
    id:'extraction-full-probability-output',severity:'high',title:'API 大量暴露完整概率向量',
    evidence:`probabilityRows=${probabilityRows}/${rows.length}`,
    meaning:'完整类别概率比仅返回 top-1 标签提供明显更多决策边界信息，会降低替代模型拟合所需查询量。',
    fix:{target:'模型 API 输出 schema',action:'业务不需要时仅返回必要标签或低精度置信度；限制类别全量分布。',regression:'相同请求不能再获得完整类别概率向量。'}
  });
  else if (vectorRatio>=0.5) findings.push({
    id:'extraction-score-vector-output',severity:'medium',title:'API 暴露多维 score/logit 向量',
    evidence:`vectorRows=${vectorRows}/${rows.length}`,
    meaning:'多维 score/logit 可作为替代模型的软标签；应结合业务必要性评估暴露范围。'
  });
  if (precisionRatio>=0.5) findings.push({
    id:'extraction-high-precision-output',severity:'medium',title:'模型输出保留高精度数值',
    evidence:`highPrecisionRows=${fullPrecisionRows}/${rows.length}`,
    meaning:'过高数值精度通常超出展示需求，会向黑盒查询者暴露更细的边界变化。'
  });
  if (duplicateQueries>=3 && inconsistentDuplicates===0) findings.push({
    id:'extraction-deterministic-oracle',severity:'medium',title:'重复查询表现为稳定确定性 Oracle',
    evidence:`duplicateQueries=${duplicateQueries}, deterministic=${deterministicDuplicates}`,
    meaning:'稳定响应有利于构造可复现的 query→soft-label 数据集；这不是漏洞本身，但会提高模型抽取效率。'
  });
  if (inconsistentDuplicates>0) findings.push({
    id:'extraction-stochastic-output',severity:'info',title:'重复查询存在输出漂移',
    evidence:`inconsistentDuplicateQueries=${inconsistentDuplicates}`,
    meaning:'输出存在随机性、动态预处理或后处理；后续拟合必须先区分随机噪声与输入差异。'
  });

  let exposureScore=0;
  if (probabilityRatio>=0.5) exposureScore+=4;
  else if (vectorRatio>=0.5) exposureScore+=2;
  if (precisionRatio>=0.5) exposureScore+=2;
  if (duplicateQueries>=3 && inconsistentDuplicates===0) exposureScore+=2;
  if (classCount>=5) exposureScore+=1;
  const exposure=exposureScore>=7?'high':exposureScore>=4?'medium':exposureScore>=2?'low':'limited';

  const nextActions=[];
  if (!rows.length) nextActions.push('先记录 query、top-1、confidence/probability/logit 和时间戳。');
  if (vectorRows) nextActions.push('按真实 preprocessing 固定 query→score transcript，先做 train/holdout 划分再评估 substitute fidelity，避免在同一 transcript 上自证成功。');
  if (classCount>1) nextActions.push(`当前 transcript 覆盖 ${classCount} 个输出类别；检查是否存在未覆盖类别和决策边界附近样本。`);
  if (duplicateQueries) nextActions.push('重复 query 已存在：用它估计模型随机性/温度/动态防护，再决定是否聚合多次响应。');

  return {
    rows:rows.length,
    uniqueQueries,
    duplicateQueries,
    deterministicDuplicates,
    inconsistentDuplicates,
    classCount,
    labelCounts:labels,
    vectorRows,
    probabilityRows,
    confidenceRows,
    highPrecisionRows:fullPrecisionRows,
    meanProbabilityEntropy:entropyCount?entropySum/entropyCount:null,
    extractionExposure:exposure,
    findings,
    nextActions,
    transcriptPreview:rows.slice(0,60).map((row)=>({ index:row.index, query:row.query.slice(0,160), label:row.label, vectorLength:row.vector.length, probabilityLike:row.probabilityLike, confidence:row.confidence }))
  };
}

function buildModelExtractionHarness(input={}) {
  let data=input;
  if (typeof input==='string') {
    try { data=JSON.parse(input); } catch { data={}; }
  }
  const task=String(data?.task||'classification');
  const script=`# NewCyber model-extraction validation harness\n# Use only challenge/authorized API transcripts.\nimport json\nimport numpy as np\nfrom sklearn.model_selection import train_test_split\nfrom sklearn.metrics import accuracy_score\n\n# rows = json.load(open('transcript.json','r',encoding='utf-8'))\n# X = ...  # reproduce the challenge preprocessing exactly\n# y_soft = ...  # probabilities/logits from transcript when provided\n# y_hard = ...  # top-1 labels\n# X_train, X_test, y_train, y_test = train_test_split(X, y_hard, test_size=0.25, random_state=1337, stratify=y_hard)\n# substitute = ...  # choose a local model appropriate for ${task}\n# substitute.fit(X_train, y_train)\n# print('holdout fidelity=', accuracy_score(y_test, substitute.predict(X_test)))\n# Keep victim-API queries out of the holdout scoring loop; report query count separately.\n`;
  return {
    task,
    harnesses:[{ backend:'scikit-learn/local substitute', project:'scikit-learn', text:script }],
    notes:['该 harness 只组织赛题/授权 transcript 的离线替代模型验证，不自动访问任何远程 API。','核心指标是独立 holdout 上与目标模型输出的一致率（fidelity/agreement），不是 substitute 自身训练准确率。']
  };
}

module.exports={ splitCsvLine, parseRows, parseVector, analyzeModelExtractionTranscript, buildModelExtractionHarness };
