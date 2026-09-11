'use strict';

const {parseRows,parseVector}=require('./ai_model_extraction');

function text(value){return String(value??'').trim();}
function num(value){if(value===null||value===undefined||value==='')return null;const n=Number(value);return Number.isFinite(n)?n:null;}
function first(row,names){const map=new Map(Object.keys(row||{}).map((key)=>[key.toLowerCase(),key]));for(const name of names){const key=map.get(name.toLowerCase());if(key!=null&&row[key]!==''&&row[key]!=null)return row[key];}return null;}
function cosine(a,b){if(!a.length||a.length!==b.length)return null;let dot=0,aa=0,bb=0;for(let i=0;i<a.length;i++){dot+=a[i]*b[i];aa+=a[i]*a[i];bb+=b[i]*b[i];}return aa>0&&bb>0?dot/Math.sqrt(aa*bb):null;}
function mae(a,b){if(!a.length||a.length!==b.length)return null;let sum=0;for(let i=0;i<a.length;i++)sum+=Math.abs(a[i]-b[i]);return sum/a.length;}
function normalizeProb(v){const rows=v.filter((x)=>Number.isFinite(x)&&x>=0);const sum=rows.reduce((a,b)=>a+b,0);if(rows.length!==v.length||!(sum>0))return null;return rows.map((x)=>x/sum);}
function jsDivergence(a,b){if(!a.length||a.length!==b.length)return null;const p=normalizeProb(a),q=normalizeProb(b);if(!p||!q)return null;const m=p.map((x,i)=>(x+q[i])/2);const kl=(x,y)=>x.reduce((s,v,i)=>v>0?s+v*Math.log2(v/Math.max(y[i],1e-15)):s,0);return(kl(p,m)+kl(q,m))/2;}
function mean(values){const rows=values.filter(Number.isFinite);return rows.length?rows.reduce((a,b)=>a+b,0)/rows.length:null;}

function normalizeRow(row,index){
  const candidate=text(first(row,['candidate_model','model','model_name','candidate','architecture','arch','fingerprint','family','substitute','student']));
  const query=text(first(row,['query_id','sample_id','id','query','input','prompt','filename','file']))||`row:${index+1}`;
  const victimLabel=text(first(row,['victim_label','target_label','oracle_label','reference_label','teacher_label','true_model_label']));
  const candidateLabel=text(first(row,['candidate_label','model_label','predicted_label','prediction','pred','student_label','substitute_label']));
  const victimVector=parseVector(first(row,['victim_probs','victim_probabilities','oracle_probs','oracle_probabilities','victim_logits','teacher_probs','teacher_logits','reference_scores']));
  const candidateVector=parseVector(first(row,['candidate_probs','candidate_probabilities','model_probs','model_probabilities','candidate_logits','student_probs','student_logits','substitute_scores']));
  const agreement=num(first(row,['agreement','fidelity','match_rate','accuracy_to_victim','victim_agreement']));
  const explicitQueries=num(first(row,['queries','query_count','samples','n_samples','count']));
  return{index:index+1,candidate,query,victimLabel:victimLabel||null,candidateLabel:candidateLabel||null,victimVector,candidateVector,agreement,explicitQueries};
}
function summarize(rows){
  const groups=new Map();
  for(const row of rows){if(!row.candidate)continue;const group=groups.get(row.candidate)||{candidate:row.candidate,rows:[],queries:new Set()};group.rows.push(row);group.queries.add(row.query);groups.set(row.candidate,group);}
  return[...groups.values()].map((group)=>{
    const labelRows=group.rows.filter((x)=>x.victimLabel&&x.candidateLabel);const labelMatches=labelRows.filter((x)=>x.victimLabel===x.candidateLabel).length;
    const vectorRows=group.rows.filter((x)=>x.victimVector.length>1&&x.victimVector.length===x.candidateVector.length);
    const directAgreement=mean(group.rows.map((x)=>x.agreement));
    const labelAgreement=labelRows.length?labelMatches/labelRows.length:null;
    const vectorCosine=mean(vectorRows.map((x)=>cosine(x.victimVector,x.candidateVector)));
    const vectorMae=mean(vectorRows.map((x)=>mae(x.victimVector,x.candidateVector)));
    const vectorJs=mean(vectorRows.map((x)=>jsDivergence(x.victimVector,x.candidateVector)));
    const explicitQueries=Math.max(0,...group.rows.map((x)=>Number(x.explicitQueries)||0));
    const queries=Math.max(group.queries.size,explicitQueries);
    const agreement=directAgreement??labelAgreement;
    const evidenceKinds=[agreement!=null?'agreement':null,vectorRows.length?'vector':null].filter(Boolean);
    return{candidate:group.candidate,rows:group.rows.length,queries,labelObservations:labelRows.length,vectorObservations:vectorRows.length,directAgreement,labelAgreement,agreement,vectorCosine,vectorMae,vectorJs,evidenceKinds};
  });
}
function candidateScore(item){
  let score=0;
  if(item.agreement!=null)score+=item.agreement*6;
  if(item.vectorCosine!=null)score+=Math.max(-1,Math.min(1,item.vectorCosine))*2;
  if(item.vectorMae!=null)score-=Math.min(2,item.vectorMae)*1.5;
  if(item.vectorJs!=null)score-=Math.min(1,item.vectorJs)*2;
  score+=Math.min(1.5,Math.log10(1+Math.max(0,item.queries))*.75);
  if(item.labelObservations>=8)score+=.25;
  if(item.vectorObservations>=8)score+=.25;
  return score;
}
function compare(a,b){return b.score-a.score||(b.agreement??-1)-(a.agreement??-1)||(b.vectorCosine??-1)-(a.vectorCosine??-1)||(a.vectorMae??Infinity)-(b.vectorMae??Infinity)||b.queries-a.queries||a.candidate.localeCompare(b.candidate);}

function analyzeModelFingerprintCandidates(input={},options={}){
  let data=input,meta={};if(input&&typeof input==='object'&&!Array.isArray(input)){meta=input;data=input.rows??input.records??input.candidates??input;}
  const rows=parseRows(data).slice(0,200000).map(normalizeRow).filter((x)=>x.candidate);
  const minQueries=Math.max(3,Number(options.minQueries??meta.minQueries??meta.min_queries??6)||6);
  const minAgreement=Math.max(0,Math.min(1,Number(options.minAgreement??meta.minAgreement??meta.min_agreement??0.6)||0.6));
  const summaries=summarize(rows).map((x)=>({...x,score:candidateScore(x),coverageOk:x.queries>=minQueries,qualityOk:x.agreement!=null?x.agreement>=minAgreement:(x.vectorCosine!=null&&x.vectorCosine>=0.95)})).sort(compare);
  const eligible=summaries.filter((x)=>x.coverageOk&&x.qualityOk);const best=eligible[0]||null;const second=eligible[1]||null;
  const margin=best&&second?best.score-second.score:null;
  const clear=Boolean(best&&(!second||(margin!=null&&margin>=0.35)||((best.agreement??0)>=0.95&&(second.agreement??0)<0.85)));
  const status=!rows.length?'gap':!best?'partial':clear?'candidate':'ambiguous';
  const findings=[];
  if(best)findings.push({id:'model-fingerprint-candidate',severity:(best.agreement??0)>=0.9?'high':'medium',title:'目标模型 Fingerprint / Candidate Model 候选',evidence:`candidate=${best.candidate}; queries=${best.queries}; agreement=${best.agreement==null?'n/a':best.agreement.toFixed(4)}; cosine=${best.vectorCosine==null?'n/a':best.vectorCosine.toFixed(4)}; score=${best.score.toFixed(3)}`,meaning:'该候选在独立 query 上与目标输出表现最接近，并满足当前覆盖/一致性阈值；仍需题目 checker 或独立 holdout 确认。'});
  if(summaries.some((x)=>x.vectorObservations>0))findings.push({id:'model-fingerprint-soft-output-evidence',severity:'info',title:'Fingerprint 排名使用了 Soft Output 证据',evidence:`candidates=${summaries.filter((x)=>x.vectorObservations>0).length}`,meaning:'完整概率/logit 形状和数值相似度能提高模型指纹区分度，但必须确保所有候选使用同一 preprocessing 与 query 集。'});
  return{
    schema:'newcyber.ai-model-fingerprint-ranker.v1',status,rows:rows.length,candidates:summaries.length,eligible:eligible.length,constraints:{minQueries,minAgreement},margin,bestCandidate:best,shortlist:summaries.slice(0,32),findings,
    result:status==='candidate'?{kind:'model-fingerprint',value:best.candidate,payload:best.candidate,displayValue:best.candidate,verified:false,confidence:'candidate',source:'model-fingerprint-ranker'}:null,
    next:status==='candidate'?'把 Top candidate 交给题目 checker / fingerprint verifier，或补一组未参与排名的 query holdout 做确认。':status==='ambiguous'?'多个模型 fingerprint 太接近；补一组对候选区分度更高的独立 query 输出，避免在同一 transcript 上继续调分。':status==='partial'?'当前 candidate model 日志还没有同时满足 query 覆盖和 fidelity/soft-output 相似度阈值。':'提供 candidate_model + query_id，并附 victim/candidate label 或概率/logit 向量的本地对比日志。',
    notes:['只分析已有本地/授权 transcript，不主动查询远程 victim。','candidate model 的最终确认应使用独立 holdout 或题目 checker，不能只用参与排名的同一批 query 自证。']
  };
}

module.exports={text,num,first,cosine,mae,jsDivergence,normalizeRow,summarize,candidateScore,compare,analyzeModelFingerprintCandidates};
