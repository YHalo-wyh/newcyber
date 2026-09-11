'use strict';

const {parseRows}=require('./ai_model_extraction');

function text(value){return String(value??'').trim();}
function num(value){if(value===null||value===undefined||value==='')return null;const n=Number(value);return Number.isFinite(n)?n:null;}
function bool(value){if(typeof value==='boolean')return value;if(typeof value==='number')return value!==0;const v=text(value).toLowerCase();if(['1','true','yes','success','passed','accepted','hit','jailbreak'].includes(v))return true;if(['0','false','no','fail','failed','rejected','miss'].includes(v))return false;return null;}
function first(row,names){const map=new Map(Object.keys(row||{}).map((k)=>[k.toLowerCase(),k]));for(const name of names){const key=map.get(name.toLowerCase());if(key!=null&&row[key]!==''&&row[key]!=null)return row[key];}return null;}
function mean(values){const rows=values.filter(Number.isFinite);return rows.length?rows.reduce((a,b)=>a+b,0)/rows.length:null;}
function tokenCount(trigger,row){const explicit=num(first(row,['token_count','tokens','length_tokens','n_tokens']));if(explicit!=null)return explicit;const s=text(trigger);if(!s)return 0;return s.split(/\s+/).filter(Boolean).length;}

function normalizeRow(row,index){
  const trigger=text(first(row,['trigger','suffix','candidate_trigger','candidate_suffix','payload','token_sequence','backdoor_trigger']));
  const prompt=text(first(row,['prompt_id','sample_id','query_id','prompt','input','query']))||`row:${index+1}`;
  const success=bool(first(row,['success','target_hit','jailbreak','accepted','passed','hit','is_success']));
  const objective=num(first(row,['reward','target_score','unsafe_score','objective','score','confidence','target_logit']));
  const baseline=num(first(row,['baseline_reward','clean_reward','control_score','baseline_score','clean_score']));
  const cleanFailure=bool(first(row,['clean_failure','benign_failure','control_failure','side_effect','collateral_failure']));
  return{index:index+1,trigger,prompt,success,objective,baseline,delta:objective!=null&&baseline!=null?objective-baseline:null,cleanFailure,tokenCount:tokenCount(trigger,row)};
}
function aggregate(rows){
  const groups=new Map();
  for(const row of rows){if(!row.trigger)continue;const group=groups.get(row.trigger)||{trigger:row.trigger,rows:[],prompts:new Set()};group.rows.push(row);group.prompts.add(row.prompt);groups.set(row.trigger,group);}
  return [...groups.values()].map((group)=>{
    const successRows=group.rows.filter((x)=>x.success!=null);const successes=successRows.filter((x)=>x.success===true).length;const cleanRows=group.rows.filter((x)=>x.cleanFailure!=null);const cleanFailures=cleanRows.filter((x)=>x.cleanFailure===true).length;
    return{trigger:group.trigger,rows:group.rows.length,prompts:group.prompts.size,asr:successRows.length?successes/successRows.length:null,successObservations:successRows.length,meanObjective:mean(group.rows.map((x)=>x.objective)),meanDelta:mean(group.rows.map((x)=>x.delta)),cleanFailureRate:cleanRows.length?cleanFailures/cleanRows.length:null,cleanObservations:cleanRows.length,tokenCount:Math.round(mean(group.rows.map((x)=>x.tokenCount))||0)};
  });
}
function compareCandidates(a,b){
  const aAsr=a.asr??-1,bAsr=b.asr??-1;const aClean=a.cleanFailureRate??0,bClean=b.cleanFailureRate??0;const aDelta=a.meanDelta??-Infinity,bDelta=b.meanDelta??-Infinity;const aObj=a.meanObjective??-Infinity,bObj=b.meanObjective??-Infinity;
  return bAsr-aAsr||aClean-bClean||b.prompts-a.prompts||bDelta-aDelta||bObj-aObj||a.tokenCount-b.tokenCount||a.trigger.localeCompare(b.trigger);
}

function analyzeUniversalTriggerCandidates(input={},options={}){
  let data=input;let meta={};
  if(input&&typeof input==='object'&&!Array.isArray(input)){meta=input;data=input.rows??input.candidates??input.records??input;}
  const rows=parseRows(data).slice(0,100000).map(normalizeRow).filter((x)=>x.trigger);
  const minPrompts=Math.max(2,Number(options.minPrompts??meta.minPrompts??meta.min_prompts??3)||3);
  const minAsr=Math.max(0,Math.min(1,Number(options.minAsr??meta.minAsr??meta.min_asr??0.6)||0.6));
  const minTokens=num(options.minTokens??meta.minTokens??meta.min_tokens);const maxTokens=num(options.maxTokens??meta.maxTokens??meta.max_tokens);
  const all=aggregate(rows).map((item)=>({...item,lengthOk:(minTokens==null||item.tokenCount>=minTokens)&&(maxTokens==null||item.tokenCount<=maxTokens),coverageOk:item.prompts>=minPrompts,asrOk:item.asr!=null&&item.asr>=minAsr}));
  const ranked=all.slice().sort((a,b)=>Number(b.lengthOk&&b.coverageOk&&b.asrOk)-Number(a.lengthOk&&a.coverageOk&&a.asrOk)||compareCandidates(a,b));
  const eligible=ranked.filter((x)=>x.lengthOk&&x.coverageOk&&x.asrOk);const best=eligible[0]||null;const second=eligible[1]||null;
  const clear=Boolean(best&&(!second||(best.asr??0)-(second.asr??0)>=0.08||((best.asr??0)>=0.95&&(second.asr??0)<0.85))));
  const status=!rows.length?'gap':!best?'partial':clear?'candidate':'ambiguous';
  const findings=[];
  if(best)findings.push({id:'universal-trigger-candidate',severity:(best.asr??0)>=0.9?'high':'medium',title:'跨多 Prompt 的 Universal Trigger 候选',evidence:`prompts=${best.prompts}; asr=${(best.asr??0).toFixed(3)}; tokenCount=${best.tokenCount}; cleanFailure=${best.cleanFailureRate==null?'n/a':best.cleanFailureRate.toFixed(3)}`,meaning:'候选在多个不同 prompt 上重复命中目标行为，并满足当前显式长度/覆盖约束；仍需题目 reward/checker 对完整候选做最终验证。'});
  if(best?.cleanFailureRate!=null&&best.cleanFailureRate>0.25)findings.push({id:'universal-trigger-control-side-effect',severity:'info',title:'Trigger 对 clean/control 行为存在明显副作用',evidence:`cleanFailureRate=${best.cleanFailureRate.toFixed(3)}`,meaning:'高副作用候选可能只是破坏输入而非稳定后门触发；排序已将 control 副作用作为惩罚项。'});
  return{
    schema:'newcyber.ai-universal-trigger-ranker.v1',status,rows:rows.length,candidates:ranked.length,eligible:eligible.length,
    constraints:{minPrompts,minAsr,minTokens,maxTokens},bestCandidate:best,shortlist:ranked.slice(0,32),findings,
    result:status==='candidate'?{kind:'universal-trigger',value:best.trigger,payload:best.trigger,displayValue:best.trigger,verified:false,confidence:'candidate',source:'universal-trigger-ranker'}:null,
    next:status==='candidate'?'把当前 trigger 交给题目本地 reward/checker 或独立 prompt holdout 验证；命中后再升级 solved。':status==='ambiguous'?'至少有两个 trigger 表现接近；补更多不同 prompt 的 reward/success 记录，让排序拉开。':status==='partial'?'已有 trigger 记录但没有候选同时满足跨-prompt 覆盖、ASR 与显式长度约束。':'提供包含 trigger/suffix、prompt_id，以及 success/reward/target_score 中至少一种信号的本地候选日志。',
    notes:['只分析已有本地/授权候选日志，不自动连接远程模型。','若题目给出 token 长度限制，必须显式传入 minTokens/maxTokens；模块不会自行假设 5–15 token。']
  };
}

module.exports={text,num,bool,normalizeRow,aggregate,compareCandidates,analyzeUniversalTriggerCandidates};
