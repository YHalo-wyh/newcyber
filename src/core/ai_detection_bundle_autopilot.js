'use strict';

const fs=require('fs/promises');
const path=require('path');
const {
  evaluateBinaryDetectionReplay,
  evaluateLossHistoryPoisonReplay,
  lossChangeMetric
}=require('./ai_domestic_detection_training');

const MAX_FILES=4000;
const MAX_FILE_BYTES=8*1024*1024;
const MAX_TOTAL_BYTES=48*1024*1024;
const STRUCTURED_EXTENSIONS=new Set(['.csv','.tsv','.json','.jsonl','.ndjson']);
const GENERATED_PREFIX='newcyber_';

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}
function normKey(value){return text(value).toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'');}
function finite(value){const n=Number(value);return Number.isFinite(n)?n:null;}
function binary(value){
  if(value===true||value===1)return 1;
  if(value===false||value===0)return 0;
  const s=text(value).toLowerCase();
  if(['1','true','yes','positive','pos','adversarial','poisoned','fake','forged','malicious'].includes(s))return 1;
  if(['0','false','no','negative','neg','clean','real','benign','normal'].includes(s))return 0;
  return null;
}

const ALIASES=Object.freeze({
  id:['id','file','filename','file_name','name','path','image','image_path','sample','sample_id'],
  truth:['truth','ground_truth','groundtruth','gt','y_true','expected','target_truth','true_label','label'],
  poisonTruth:['poison_truth','poisoned','is_poisoned','is_poison','poison_label'],
  prediction:['predicted','prediction','pred','y_pred','detected','result','decision','is_adversarial','is_poisoned','is_fake','value'],
  score:['score','probability','prob','confidence','pred_score','prediction_score','fraud_probability','fake_probability'],
  threshold:['threshold','decision_threshold','score_threshold'],
  thresholdRatio:['threshold_ratio','poison_ratio','top_ratio','selection_ratio']
});

function findKey(row,kind){
  if(!row||typeof row!=='object'||Array.isArray(row))return null;
  const map=new Map(Object.keys(row).map((key)=>[normKey(key),key]));
  for(const alias of ALIASES[kind]||[]){if(map.has(alias))return map.get(alias);}
  return null;
}

function parseDelimitedLine(line,delimiter){
  const out=[];let current='';let quoted=false;
  for(let i=0;i<line.length;i+=1){
    const ch=line[i];
    if(ch==='"'){
      if(quoted&&line[i+1]==='"'){current+='"';i+=1;continue;}
      quoted=!quoted;continue;
    }
    if(ch===delimiter&&!quoted){out.push(current);current='';continue;}
    current+=ch;
  }
  out.push(current);return out;
}

function parseDelimited(input,delimiter=','){
  const lines=String(input||'').replace(/^\uFEFF/,'').split(/\r?\n/).filter((line)=>line.trim().length>0);
  if(lines.length<2)return[];
  const headers=parseDelimitedLine(lines[0],delimiter).map((x)=>x.trim());
  if(!headers.length||headers.length>512)return[];
  const rows=[];
  for(const line of lines.slice(1,200001)){
    const values=parseDelimitedLine(line,delimiter);const row={};
    headers.forEach((header,index)=>{row[header]=values[index]??'';});rows.push(row);
  }
  return rows;
}

function extractJsonRows(value){
  if(Array.isArray(value))return value.filter((x)=>x&&typeof x==='object'&&!Array.isArray(x));
  if(!value||typeof value!=='object')return[];
  for(const key of ['rows','results','samples','predictions','detections','items','data']){
    if(Array.isArray(value[key]))return value[key].filter((x)=>x&&typeof x==='object'&&!Array.isArray(x));
  }
  return[];
}

function parseJsonLines(input){
  const rows=[];
  for(const line of String(input||'').split(/\r?\n/).slice(0,200000)){
    if(!line.trim())continue;
    try{const value=JSON.parse(line);if(value&&typeof value==='object'&&!Array.isArray(value))rows.push(value);}catch{}
  }
  return rows;
}

function thresholdFromContainer(container,rows){
  if(container&&typeof container==='object'&&!Array.isArray(container)){
    const key=findKey(container,'threshold');const value=key?finite(container[key]):null;if(value!=null)return{value,source:`container:${key}`};
  }
  for(const row of rows.slice(0,32)){
    const key=findKey(row,'threshold');const value=key?finite(row[key]):null;if(value!=null)return{value,source:`row:${key}`};
  }
  return null;
}

function thresholdRatioFromContainer(container,rows){
  if(container&&typeof container==='object'&&!Array.isArray(container)){
    const key=findKey(container,'thresholdRatio');const value=key?finite(container[key]):null;if(value!=null&&value>0&&value<=1)return{value,source:`container:${key}`};
  }
  for(const row of rows.slice(0,32)){
    const key=findKey(row,'thresholdRatio');const value=key?finite(row[key]):null;if(value!=null&&value>0&&value<=1)return{value,source:`row:${key}`};
  }
  return null;
}

function binaryCandidate(rows,container=null){
  if(!rows.length)return null;
  const sample=rows.find((row)=>findKey(row,'truth')&&(findKey(row,'prediction')||findKey(row,'score')));
  if(!sample)return null;
  const truthKey=findKey(sample,'truth');const predictionKey=findKey(sample,'prediction');const scoreKey=findKey(sample,'score');const idKey=findKey(sample,'id');
  const threshold=predictionKey?null:thresholdFromContainer(container,rows);
  if(!predictionKey&&scoreKey&&!threshold)return{kind:'binary-gap',reason:'score-without-explicit-threshold',columns:{truth:truthKey,score:scoreKey,id:idKey}};
  const normalized=[];
  for(let index=0;index<rows.length;index+=1){
    const row=rows[index];const tk=findKey(row,'truth')||truthKey;const pk=findKey(row,'prediction')||predictionKey;const sk=findKey(row,'score')||scoreKey;const ik=findKey(row,'id')||idKey;
    const truth=binary(row[tk]);if(truth==null)continue;
    const item={id:text(ik?row[ik]:`row-${index+1}`),truth};
    if(pk){const predicted=binary(row[pk]);if(predicted==null)continue;item.predicted=predicted;}
    else if(sk){const score=finite(row[sk]);if(score==null)continue;item.score=score;}
    else continue;
    normalized.push(item);
  }
  if(normalized.length<4)return{kind:'binary-gap',reason:'insufficient-valid-rows',rows:normalized.length,columns:{truth:truthKey,prediction:predictionKey,score:scoreKey,id:idKey}};
  return{kind:'binary',rows:normalized,threshold:threshold?.value??null,thresholdSource:threshold?.source||null,columns:{truth:truthKey,prediction:predictionKey,score:scoreKey,id:idKey}};
}

function lossColumns(row){
  if(!row||typeof row!=='object')return[];
  return Object.keys(row).filter((key)=>/^(?:loss|epoch[_ -]?\d+[_ -]?loss|loss[_ -]?epoch)[_ -]?\d+$/i.test(key)).sort((a,b)=>{
    const an=Number((a.match(/\d+/)||['0'])[0]);const bn=Number((b.match(/\d+/)||['0'])[0]);return an-bn||a.localeCompare(b);
  });
}

function lossesFromRow(row){
  for(const key of ['losses','loss_history','lossHistory','history']){
    if(Array.isArray(row?.[key]))return row[key].map(Number);
  }
  const cols=lossColumns(row);if(cols.length>=2)return cols.map((key)=>Number(row[key]));
  return null;
}

function lossHistoryCandidate(rows,container=null){
  if(!rows.length)return null;
  const parsed=[];const truth=[];
  for(let index=0;index<rows.length;index+=1){
    const row=rows[index];const losses=lossesFromRow(row);const metric=lossChangeMetric(losses);if(!metric)continue;
    const idKey=findKey(row,'id');const id=text(idKey?row[idKey]:`row-${index+1}`);
    parsed.push({id,losses});
    const truthKey=findKey(row,'poisonTruth');if(truthKey&&binary(row[truthKey])===1)truth.push(id);
  }
  if(parsed.length<4)return null;
  const ratio=thresholdRatioFromContainer(container,rows);
  if(ratio){
    return{kind:'loss-history',rows:parsed,thresholdRatio:ratio.value,thresholdRatioSource:ratio.source,poisonTruth:truth.length?truth:null};
  }
  const ranking=parsed.map((row)=>({id:row.id,...lossChangeMetric(row.losses)})).sort((a,b)=>b.meanAbsoluteChange-a.meanAbsoluteChange||b.rmsChange-a.rmsChange||a.id.localeCompare(b.id));
  return{kind:'loss-history-ranking',rows:parsed.length,ranking:ranking.slice(0,512),reason:'threshold-ratio-not-evidenced',poisonTruth:truth.length?truth:null};
}

async function walkStructured(root,options={}){
  const maxFiles=Math.max(1,Math.min(20000,Number(options.maxFiles)||MAX_FILES));const out=[];let total=0;
  async function visit(dir){
    if(out.length>=maxFiles||total>=MAX_TOTAL_BYTES)return;
    let entries;try{entries=await fs.readdir(dir,{withFileTypes:true});}catch{return;}
    for(const entry of entries){
      if(out.length>=maxFiles||total>=MAX_TOTAL_BYTES)break;
      if(entry.name==='.git'||entry.name==='node_modules'||entry.name==='__pycache__')continue;
      const full=path.join(dir,entry.name);
      if(entry.isDirectory()){await visit(full);continue;}
      if(!entry.isFile()||entry.name.startsWith(GENERATED_PREFIX))continue;
      const ext=path.extname(entry.name).toLowerCase();if(!STRUCTURED_EXTENSIONS.has(ext))continue;
      let stat;try{stat=await fs.stat(full);}catch{continue;}
      if(stat.size<=0||stat.size>MAX_FILE_BYTES||total+stat.size>MAX_TOTAL_BYTES)continue;
      total+=stat.size;out.push({path:full,relative:path.relative(root,full).replace(/\\/g,'/'),ext,size:stat.size});
    }
  }
  await visit(root);return out;
}

async function parseStructuredFile(file){
  const raw=await fs.readFile(file.path,'utf8');
  if(file.ext==='.csv'||file.ext==='.tsv')return{rows:parseDelimited(raw,file.ext==='.tsv'?'\t':','),container:null};
  if(file.ext==='.jsonl'||file.ext==='.ndjson')return{rows:parseJsonLines(raw),container:null};
  let value;try{value=JSON.parse(raw);}catch{return{rows:[],container:null,error:'invalid-json'};}
  return{rows:extractJsonRows(value),container:value};
}

async function runAiDetectionBundleAutopilot(root,analysis={},options={}){
  const files=await walkStructured(root,options);const evaluations=[];const gaps=[];const findings=[];
  for(const file of files){
    let parsed;try{parsed=await parseStructuredFile(file);}catch(error){gaps.push({file:file.relative,reason:'parse-error',detail:String(error?.message||error).slice(0,300)});continue;}
    if(!parsed.rows.length)continue;
    const binaryInput=binaryCandidate(parsed.rows,parsed.container);
    if(binaryInput?.kind==='binary'){
      const result=evaluateBinaryDetectionReplay({rows:binaryInput.rows,...(binaryInput.threshold!=null?{threshold:binaryInput.threshold}:{})});
      const item={file:file.relative,kind:'binary-detection',columns:binaryInput.columns,threshold:binaryInput.threshold,thresholdSource:binaryInput.thresholdSource,result};evaluations.push(item);
      for(const finding of result.findings||[])findings.push({...finding,file:file.relative,evidence:`${finding.evidence}; source=${file.relative}`});
    }else if(binaryInput?.kind==='binary-gap')gaps.push({file:file.relative,reason:binaryInput.reason,columns:binaryInput.columns,rows:binaryInput.rows||parsed.rows.length});

    const lossInput=lossHistoryCandidate(parsed.rows,parsed.container);
    if(lossInput?.kind==='loss-history'){
      const result=evaluateLossHistoryPoisonReplay({rows:lossInput.rows,thresholdRatio:lossInput.thresholdRatio,...(lossInput.poisonTruth?{poisonTruth:lossInput.poisonTruth}:{})});
      evaluations.push({file:file.relative,kind:'loss-history-poison',thresholdRatio:lossInput.thresholdRatio,thresholdRatioSource:lossInput.thresholdRatioSource,result});
      for(const finding of result.findings||[])findings.push({...finding,file:file.relative,evidence:`${finding.evidence}; source=${file.relative}`});
    }else if(lossInput?.kind==='loss-history-ranking'){
      evaluations.push({file:file.relative,kind:'loss-history-ranking',reason:lossInput.reason,ranking:lossInput.ranking,rows:lossInput.rows});
      findings.push({id:'poison-loss-history-ranking-candidate',severity:'info',title:'发现可自动排序的 loss-history 数据',file:file.relative,evidence:`rows=${lossInput.rows}; threshold ratio not evidenced`,meaning:'已生成异常变化排名，但未发现明确 threshold_ratio，因此不猜测投毒集合大小。'});
    }
  }

  let correlation=null;
  try{
    const {runDetectionTableCorrelation}=require('./ai_detection_table_correlation');
    correlation=await runDetectionTableCorrelation(root,options);
    for(const item of correlation.correlations||[])evaluations.push({file:item.predictionFile,kind:'split-table-correlation',truthFile:item.truthFile,predictionFile:item.predictionFile,matchedRows:item.matchedRows,coverage:item.coverage,confidence:item.confidence,result:item.result});
    for(const gap of correlation.gaps||[])gaps.push({source:'split-table-correlation',...gap});
    for(const finding of correlation.findings||[])findings.push(finding);
  }catch(error){
    gaps.push({source:'split-table-correlation',reason:'correlation-exception',detail:String(error?.message||error).slice(0,300)});
  }

  const binaryRuns=evaluations.filter((x)=>x.kind==='binary-detection'||x.kind==='split-table-correlation');
  const lossRuns=evaluations.filter((x)=>x.kind.startsWith('loss-history'));
  const effective=binaryRuns.filter((x)=>x.result?.verdict==='candidate-effective').length+evaluations.filter((x)=>x.kind==='loss-history-poison'&&x.result?.verdict==='candidate-effective').length;
  const status=evaluations.length?(gaps.length?'partial':'evaluated'):(gaps.length?'gap':'not-applicable');
  return{
    schema:'newcyber.ai-detection-bundle-autopilot.v2',status,
    summary:{structuredFiles:files.length,evaluations:evaluations.length,binaryRuns:binaryRuns.length,lossHistoryRuns:lossRuns.length,splitTableCorrelations:Number(correlation?.summary?.correlations)||0,effectiveCandidates:effective,gaps:gaps.length},
    evaluations:evaluations.slice(0,64),gaps:gaps.slice(0,64),findings:findings.slice(0,128),correlation,
    next:status==='not-applicable'?'未发现可确定解释的检测结果表。':status==='gap'?'发现检测型结构化数据，但缺少显式 threshold、可靠 truth/prediction 配对或足够样本。':gaps.length?'已自动复算可验证部分，其余结构化结果保留为 GAP。':'已自动复算检测结果；最终是否可提交仍以题目 scorer/verifier 为准。',
    notes:['不会把 prediction-only CSV 当 ground truth，也不会默认 score threshold=0.5。','分离 truth/prediction 表只按稳定样本 ID 和高置信文件角色关联，不按行号强拼。','loss-history 没有显式 threshold_ratio 时只给完整异常排名，不猜投毒样本数量。','本模块只读取结构化结果文件，不执行题目脚本或加载不受信模型。']
  };
}

module.exports={ALIASES,parseDelimited,extractJsonRows,parseJsonLines,binaryCandidate,lossColumns,lossesFromRow,lossHistoryCandidate,walkStructured,parseStructuredFile,runAiDetectionBundleAutopilot};