const { parseRows,parseVector }=require('./ai_model_extraction');

function pick(row,names) {
  for (const name of names) if (row[name]!==undefined&&row[name]!==null&&String(row[name]).trim()!=='') return row[name];
  return null;
}

function parseBoxes(value) {
  if (Array.isArray(value)) {
    if (value.length&&Array.isArray(value[0])) return value.flatMap((x)=>parseBoxes(x));
    if (value.length>=4&&value.every((x)=>Number.isFinite(Number(x)))) return [value.map(Number)];
  }
  if (value&&typeof value==='object') {
    const keys=['x','y','w','h'];
    if (keys.every((k)=>Number.isFinite(Number(value[k])))) return [[Number(value.x),Number(value.y),Number(value.w),Number(value.h)]];
    if (Array.isArray(value.points)) return parseBoxes(value.points.flat());
    return Object.values(value).flatMap((x)=>parseBoxes(x));
  }
  const text=String(value??'').trim();
  if (!text) return [];
  try { return parseBoxes(JSON.parse(text)); } catch {}
  const nums=text.split(/[|,;\s]+/).map(Number).filter(Number.isFinite);
  return nums.length>=4?[nums.slice(0,4)]:[];
}

function precisionOf(value) {
  const matches=String(value??'').match(/\.\d+/g)||[];
  return matches.reduce((m,x)=>Math.max(m,x.length-1),0);
}

function normalizedText(value) { return String(value??'').trim(); }

function analyzeOcrExtractionTranscript(input,options={}) {
  const rawRows=parseRows(input);
  const rows=[];
  const charset=new Set();
  let confidenceRows=0; let charConfidenceRows=0; let boxRows=0; let highPrecisionBoxRows=0; let logitRows=0;
  let totalChars=0;
  const duplicateMap=new Map();

  for (let i=0;i<rawRows.length;i+=1) {
    const row=rawRows[i]||{};
    const query=normalizedText(pick(row,['query','input','image','image_id','sample','file','path','request'])??`row:${i+1}`);
    const text=normalizedText(pick(row,['text','ocr_text','prediction','output','result','recognized_text','transcript']));
    const confidences=parseVector(pick(row,['char_confidences','character_confidences','word_confidences','confidences','confidence_vector']));
    const confidence=Number(pick(row,['confidence','score','mean_confidence']));
    const logits=parseVector(pick(row,['logits','scores','probabilities','probs']));
    const boxesRaw=pick(row,['boxes','bboxes','bounding_boxes','polygons','regions']);
    const boxes=parseBoxes(boxesRaw);
    if (confidences.length) {
      confidenceRows+=1;
      if (text&&confidences.length>=Math.max(1,text.length-2)) charConfidenceRows+=1;
    } else if (Number.isFinite(confidence)) confidenceRows+=1;
    if (boxes.length) { boxRows+=1; if (precisionOf(boxesRaw)>=4) highPrecisionBoxRows+=1; }
    if (logits.length>2) logitRows+=1;
    for (const ch of text) if (!/\s/.test(ch)) charset.add(ch);
    totalChars+=text.length;
    const signature=`${text}|${confidences.length?confidences.map((x)=>Number(x).toPrecision(10)).join(','):Number.isFinite(confidence)?confidence:''}|${boxes.length?JSON.stringify(boxes):''}`;
    const list=duplicateMap.get(query)||[]; list.push(signature); duplicateMap.set(query,list);
    rows.push({index:i+1,query,text,confidence:Number.isFinite(confidence)?confidence:null,confidenceCount:confidences.length,boxCount:boxes.length,logitCount:logits.length});
  }

  let duplicateQueries=0; let stableDuplicates=0; let driftingDuplicates=0;
  for (const list of duplicateMap.values()) {
    if (list.length<2) continue;
    duplicateQueries+=1;
    if (new Set(list).size===1) stableDuplicates+=1;
    else driftingDuplicates+=1;
  }

  const total=Math.max(rawRows.length,1);
  const findings=[];
  if (charConfidenceRows/total>=0.4) findings.push({
    id:'ocr-char-confidence-exposure',severity:'high',title:'OCR API 大量暴露字符/词级置信度',evidence:`charConfidenceRows=${charConfidenceRows}/${rawRows.length}`,
    meaning:'字符级 soft label 比最终文本包含更细的决策信息，可显著增强黑盒蒸馏/模型窃取数据质量。'
  });
  if (logitRows/total>=0.3) findings.push({
    id:'ocr-logit-exposure',severity:'high',title:'OCR API 暴露多维 logits/probabilities',evidence:`logitRows=${logitRows}/${rawRows.length}`,
    meaning:'完整类别分布比字符结果本身泄露更多分类边界信息；业务不需要时应收敛输出。'
  });
  if (boxRows/total>=0.5) findings.push({
    id:'ocr-layout-exposure',severity:'medium',title:'OCR API 持续返回布局/Bounding Box',evidence:`boxRows=${boxRows}/${rawRows.length}, highPrecision=${highPrecisionBoxRows}`,
    meaning:'检测框本身常是业务必要输出，但会同时暴露检测器布局能力；与字符置信度组合时更适合构造多任务替代模型。'
  });
  if (highPrecisionBoxRows/total>=0.4) findings.push({
    id:'ocr-high-precision-layout',severity:'info',title:'OCR 布局坐标保留较高数值精度',evidence:`highPrecisionBoxRows=${highPrecisionBoxRows}/${rawRows.length}`,
    meaning:'高精度坐标可能超出前端展示需求；可评估量化坐标是否满足业务。'
  });
  if (duplicateQueries>=3&&driftingDuplicates===0) findings.push({
    id:'ocr-deterministic-oracle',severity:'medium',title:'OCR 重复查询表现为稳定 Oracle',evidence:`duplicates=${duplicateQueries}, stable=${stableDuplicates}`,
    meaning:'稳定输出便于构造可复现 query→text/layout/soft-label 数据集；这是抽取效率因素，不单独等于安全漏洞。'
  });

  const expected=String(options.expectedCharset||'');
  const missing=expected?[...new Set(expected)].filter((ch)=>!charset.has(ch)&&!(/\s/.test(ch))):[];
  const exposureScore=(charConfidenceRows?3:0)+(logitRows?4:0)+(boxRows/total>=0.5?1:0)+(duplicateQueries>=3&&driftingDuplicates===0?2:0);
  const exposure=exposureScore>=7?'high':exposureScore>=4?'medium':exposureScore>=2?'low':'limited';
  const nextActions=[];
  nextActions.push(`当前 transcript 覆盖 ${charset.size} 个非空白字符、${totalChars} 个输出字符；先按字符/语言/版式划分 train 与 holdout，再评估 substitute fidelity。`);
  if (missing.length) nextActions.push(`预期字符集中仍有 ${missing.length} 个字符未覆盖：${missing.slice(0,80).join('')}`);
  if (boxRows) nextActions.push('布局任务与识别任务分开评分：文本用 CER/WER/完全一致率，检测框用 IoU/匹配率，最后再看端到端 fidelity。');
  if (confidenceRows) nextActions.push('比较仅最终文本、文本+置信度、文本+布局三种 transcript 的替代模型收益，避免把不必要的 soft-label 暴露留在生产接口。');

  return {
    rows:rawRows.length,
    uniqueQueries:duplicateMap.size,
    duplicateQueries,stableDuplicates,driftingDuplicates,
    charsetSize:charset.size,charset:[...charset].slice(0,1000).join(''),totalOutputChars:totalChars,averageOutputLength:rawRows.length?totalChars/rawRows.length:0,
    confidenceRows,charConfidenceRows,boxRows,highPrecisionBoxRows,logitRows,
    expectedCharsetMissing:missing,
    extractionExposure:exposure,
    findings,nextActions,
    preview:rows.slice(0,80),
    notes:['本模块只分析已有赛题/授权 OCR transcript，不主动调用远程 OCR 服务。','OCR 模型窃取是否成功应以独立 holdout 上的文本/布局 fidelity 判断，而不是替代模型训练集准确率。']
  };
}

function buildOcrExtractionHarness(input={}) {
  let data=input;
  if (typeof input==='string') { try { data=JSON.parse(input); } catch { data={}; } }
  const script=`# NewCyber OCR extraction validation harness\n# Offline only: use an authorized/exported transcript.\n# 1) Reproduce image resize/normalize/tokenization exactly.\n# 2) Split by source document/image family before training to avoid leakage.\n# 3) Train a local OCR/detector substitute on query -> text/box targets.\n# 4) Report on independent holdout:\n#    - exact text agreement\n#    - CER/WER\n#    - box IoU / matched detections\n#    - total victim query count used to build transcript\n# Do not query the victim inside the holdout scoring loop.\n`;
  return {task:String(data?.task||'ocr'),harnesses:[{backend:'local OCR substitute',text:script}],notes:['具体 OCR 框架按赛题已有模型/依赖选择；NewCyber 不假装知道官方模型架构。']};
}

module.exports={parseBoxes,analyzeOcrExtractionTranscript,buildOcrExtractionHarness};
