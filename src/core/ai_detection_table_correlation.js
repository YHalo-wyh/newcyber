'use strict';

const path=require('path');
const {walkStructured,parseStructuredFile}=require('./ai_detection_bundle_autopilot');
const {evaluateBinaryDetectionReplay}=require('./ai_domestic_detection_training');

function text(value){return String(value??'').trim();}
function norm(value){return text(value).toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,'');}
function binary(value){
  if(value===true||value===1)return 1;if(value===false||value===0)return 0;
  const s=text(value).toLowerCase();
  if(['1','true','yes','positive','pos','adversarial','poisoned','fake','forged','malicious'].includes(s))return 1;
  if(['0','false','no','negative','neg','clean','real','benign','normal'].includes(s))return 0;
  return null;
}
const ID_KEYS=['id','file','filename','file_name','name','path','image','image_path','sample','sample_id'];
const TRUTH_KEYS=['truth','ground_truth','groundtruth','gt','y_true','expected','target_truth','true_label','label'];
const PRED_KEYS=['predicted','prediction','pred','y_pred','detected','result','decision','is_adversarial','is_poisoned','is_fake','value'];

function findKey(row,aliases){
  if(!row||typeof row!=='object'||Array.isArray(row))return null;
  const map=new Map(Object.keys(row).map((key)=>[norm(key),key]));
  for(const alias of aliases)if(map.has(alias))return map.get(alias);
  return null;
}
function fileRoleScore(file,role){
  const base=path.basename(text(file)).toLowerCase();
  if(role==='truth'){
    let score=0;if(/ground[_ -]?truth|truth|answer|expected/.test(base))score+=4;if(/labels?|targets?|reference/.test(base))score+=3;return score;
  }
  let score=0;if(/pred(?:iction)?|result|detect|output|submit|submission/.test(base))score+=4;if(/score|infer|eval/.test(base))score+=2;return score;
}
function tableProfile(file,rows){
  const sample=rows.find((row)=>findKey(row,ID_KEYS));if(!sample)return null;
  const idKey=findKey(sample,ID_KEYS);const truthKey=findKey(sample,TRUTH_KEYS);const predKey=findKey(sample,PRED_KEYS);
  if(!idKey||(!truthKey&&!predKey))return null;
  const role=truthKey&&predKey?'both':truthKey?'truth':'prediction';
  const values=new Map();let duplicates=0,invalid=0;
  const valueKey=role==='truth'?truthKey:role==='prediction'?predKey:null;
  if(valueKey){
    for(const row of rows){
      const ik=findKey(row,ID_KEYS)||idKey;const vk=findKey(row,role==='truth'?TRUTH_KEYS:PRED_KEYS)||valueKey;
      const id=text(row[ik]);const value=binary(row[vk]);if(!id||value==null){invalid+=1;continue;}
      if(values.has(id)){duplicates+=1;continue;}values.set(id,value);
    }
  }
  return{file,role,idKey,truthKey,predKey,rows:rows.length,values,duplicates,invalid,roleScore:fileRoleScore(file,role)};
}
function correlationCandidate(truth,prediction){
  if(!truth||!prediction||truth.role!=='truth'||prediction.role!=='prediction')return null;
  if(truth.duplicates||prediction.duplicates)return null;
  if(truth.roleScore<2||prediction.roleScore<2)return null;
  const ids=[];for(const id of truth.values.keys())if(prediction.values.has(id))ids.push(id);
  const smaller=Math.min(truth.values.size,prediction.values.size);const coverage=smaller?ids.length/smaller:0;
  if(ids.length<4||coverage<0.8)return null;
  const rows=ids.map((id)=>({id,truth:truth.values.get(id),predicted:prediction.values.get(id)}));
  const result=evaluateBinaryDetectionReplay({rows});
  return{
    truthFile:truth.file,predictionFile:prediction.file,matchedRows:ids.length,coverage,
    truthRows:truth.values.size,predictionRows:prediction.values.size,
    confidence:Math.min(1,0.35+coverage*0.45+Math.min(0.2,(truth.roleScore+prediction.roleScore)/40)),
    result
  };
}

async function runDetectionTableCorrelation(root,options={}){
  const files=await walkStructured(root,options);const profiles=[];const parseErrors=[];
  for(const file of files){
    let parsed;try{parsed=await parseStructuredFile(file);}catch(error){parseErrors.push({file:file.relative,error:String(error?.message||error).slice(0,300)});continue;}
    if(!parsed.rows?.length)continue;
    const profile=tableProfile(file.relative,parsed.rows);if(profile)profiles.push(profile);
  }
  const truth=profiles.filter((x)=>x.role==='truth');const predictions=profiles.filter((x)=>x.role==='prediction');const candidates=[];
  for(const t of truth)for(const p of predictions){const pair=correlationCandidate(t,p);if(pair)candidates.push(pair);}
  candidates.sort((a,b)=>b.matchedRows-a.matchedRows||b.confidence-a.confidence||a.truthFile.localeCompare(b.truthFile));
  const chosen=[];const usedTruth=new Set();const usedPred=new Set();
  for(const item of candidates){
    if(usedTruth.has(item.truthFile)||usedPred.has(item.predictionFile))continue;
    usedTruth.add(item.truthFile);usedPred.add(item.predictionFile);chosen.push(item);if(chosen.length>=16)break;
  }
  const findings=[];
  for(const item of chosen){
    findings.push({id:'detection-split-table-correlated',severity:'info',title:'已关联分离的 truth / prediction 结果表',file:item.predictionFile,evidence:`truth=${item.truthFile}; prediction=${item.predictionFile}; rows=${item.matchedRows}; coverage=${item.coverage.toFixed(4)}`,meaning:'通过稳定样本 ID 与文件角色证据关联两张表，再独立复算二分类指标；未依赖行顺序。'});
    for(const finding of item.result.findings||[])findings.push({...finding,file:item.predictionFile,evidence:`${finding.evidence}; truth=${item.truthFile}; prediction=${item.predictionFile}`});
  }
  const ambiguous=(truth.length&&predictions.length&&!chosen.length)?[{reason:'no-high-confidence-table-pair',truthFiles:truth.map((x)=>x.file).slice(0,16),predictionFiles:predictions.map((x)=>x.file).slice(0,16)}]:[];
  const status=chosen.length?'evaluated':ambiguous.length?'gap':'not-applicable';
  return{
    schema:'newcyber.ai-detection-table-correlation.v1',status,
    summary:{structuredFiles:files.length,profiles:profiles.length,truthTables:truth.length,predictionTables:predictions.length,correlations:chosen.length,parseErrors:parseErrors.length},
    correlations:chosen,gaps:ambiguous,parseErrors:parseErrors.slice(0,32),findings:findings.slice(0,128),
    next:status==='evaluated'?'已按样本 ID 自动关联 truth 与 prediction，并复算指标；最终提交仍以题目 scorer 为准。':status==='gap'?'同时发现 truth/prediction 表，但文件角色或 ID 覆盖不足，拒绝强行配对。':'未发现需要跨文件关联的检测结果表。',
    notes:['关联要求显式样本 ID、至少 4 个重合样本、>=80% 较小表覆盖率，并要求文件名提供 truth/prediction 角色证据。','不会按行号直接拼接两张表，也不会在多重候选间随机选择。']
  };
}

module.exports={ID_KEYS,TRUTH_KEYS,PRED_KEYS,findKey,fileRoleScore,tableProfile,correlationCandidate,runDetectionTableCorrelation};
