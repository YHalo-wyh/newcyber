'use strict';

const {parseRows}=require('./ai_privacy');

function num(value){const n=Number(value);return Number.isFinite(n)?n:null;}
function text(value){return String(value??'').trim();}
function bool(value){
  if(typeof value==='boolean')return value;
  const v=text(value).toLowerCase();
  if(['1','true','yes','success','pass','accepted','hit'].includes(v))return true;
  if(['0','false','no','fail','failed','reject','rejected'].includes(v))return false;
  return null;
}
function first(row,names){
  const lower=new Map(Object.keys(row||{}).map((k)=>[k.toLowerCase(),k]));
  for(const name of names){const key=lower.get(name.toLowerCase());if(key!=null&&row[key]!==''&&row[key]!=null)return row[key];}
  return null;
}
function vector(value){
  if(Array.isArray(value))return value.map(Number).filter(Number.isFinite);
  const raw=text(value);if(!raw)return null;
  try{const v=JSON.parse(raw);return Array.isArray(v)?v.map(Number).filter(Number.isFinite):null;}catch{return null;}
}
function distance(a,b,norm='linf'){
  if(!a||!b||a.length!==b.length||!a.length)return null;
  const d=a.map((x,i)=>Math.abs(x-b[i]));
  if(norm==='l2')return Math.sqrt(d.reduce((s,x)=>s+x*x,0));
  if(norm==='l1')return d.reduce((s,x)=>s+x,0);
  return Math.max(...d);
}
function metaAndRows(input){
  if(input&&typeof input==='object'&&!Array.isArray(input))return{meta:input,rows:Array.isArray(input.rows)?input.rows.slice(0,50000):parseRows(input)};
  return{meta:{},rows:parseRows(input).slice(0,50000)};
}
function inferNorm(meta,rows){
  const explicit=text(meta.norm||meta.distanceNorm||meta.metric).toLowerCase();
  if(['linf','l∞','inf','infinity'].includes(explicit))return'linf';
  if(['l2','2'].includes(explicit))return'l2';
  if(['l1','1'].includes(explicit))return'l1';
  const keys=new Set(rows.flatMap((r)=>Object.keys(r||{}).map((k)=>k.toLowerCase())));
  if(keys.has('linf')||keys.has('l_inf'))return'linf';
  if(keys.has('l2'))return'l2';
  if(keys.has('l1'))return'l1';
  return'linf';
}
function rowDistance(row,norm){
  const aliases=norm==='l2'?['l2','distance_l2','perturbation_l2']:norm==='l1'?['l1','distance_l1','perturbation_l1']:['linf','l_inf','distance_linf','perturbation_linf'];
  const direct=num(first(row,aliases));if(direct!=null)return direct;
  const generic=num(first(row,['distance','dist','perturbation','norm_value']));if(generic!=null)return generic;
  const original=vector(first(row,['original','original_vector','clean','x0','base']));
  const candidate=vector(first(row,['candidate','adversarial','adv','x','vector']));
  return distance(original,candidate,norm);
}
function rowObjective(row){
  return num(first(row,['target_score','target_prob','target_probability','objective','score','confidence','probability','logit','reward']));
}
function rowSuccess(row,meta){
  const explicit=bool(first(row,['success','accepted','passed','is_success','hit']));if(explicit!=null)return explicit;
  const predicted=text(first(row,['predicted_label','prediction','pred','label','top1']));
  const target=text(first(row,['target_label','target','goal_label'])??meta.targetLabel??meta.target_label);
  if(predicted&&target)return predicted===target;
  const baseline=text(first(row,['baseline_label','clean_label','original_label'])??meta.originalLabel??meta.original_label);
  if(predicted&&baseline&&!target)return predicted!==baseline;
  return null;
}
function queryIndex(row,index){return num(first(row,['query','query_id','query_index','iteration','step','id']))??index+1;}

function analyzeBlackboxAdversarialTranscript(input={}){
  const {meta,rows}=metaAndRows(input);const norm=inferNorm(meta,rows);
  const epsilon=num(meta.epsilon??meta.eps??meta.budget??meta.maxDistance);
  const queryBudget=num(meta.queryBudget??meta.query_budget??meta.maxQueries??meta.max_queries);
  const maximize=String(meta.objectiveDirection||meta.objective_direction||'maximize').toLowerCase()!=='minimize';
  const candidates=[];
  for(let index=0;index<rows.length;index++){
    const row=rows[index]||{};const dist=rowDistance(row,norm);const objective=rowObjective(row);const success=rowSuccess(row,meta);const query=queryIndex(row,index);
    const withinBudget=epsilon==null||dist==null?null:dist<=epsilon+1e-12;
    if(dist==null&&objective==null&&success==null)continue;
    candidates.push({index:index+1,query,distance:dist,objective,success,withinBudget,prediction:text(first(row,['predicted_label','prediction','pred','label','top1']))||null,targetLabel:text(first(row,['target_label','target','goal_label'])??meta.targetLabel??meta.target_label)||null});
  }
  const score=(x)=>{
    const success=(x.success===true&&x.withinBudget!==false)?3:x.success===true?2:0;
    const budget=x.withinBudget===true?1:x.withinBudget===false?-1:0;
    const objective=Number.isFinite(x.objective)?(maximize?x.objective:-x.objective):0;
    const dist=Number.isFinite(x.distance)?x.distance:1e9;
    return{success,budget,objective,dist};
  };
  candidates.sort((a,b)=>{
    const A=score(a),B=score(b);
    return B.success-A.success||B.budget-A.budget||B.objective-A.objective||A.dist-B.dist||a.query-b.query;
  });
  const successful=candidates.filter((x)=>x.success===true);
  const validSuccess=successful.filter((x)=>x.withinBudget!==false);
  const overBudget=successful.filter((x)=>x.withinBudget===false);
  const best=validSuccess[0]||candidates[0]||null;
  const maxQuery=candidates.reduce((m,x)=>Math.max(m,Number(x.query)||0),0);
  const queryBudgetExceeded=queryBudget!=null&&maxQuery>queryBudget;
  const findings=[];
  if(validSuccess.length)findings.push({id:'blackbox-adversarial-valid-candidate',severity:'info',title:'黑盒查询记录中存在预算内成功候选',evidence:`valid=${validSuccess.length}; best_query=${best?.query}; norm=${norm}; distance=${best?.distance??'n/a'}; epsilon=${epsilon??'n/a'}`,meaning:'已有 oracle/transcript 证据表明至少一个候选满足攻击成功条件，且未观察到扰动预算超限。若比赛还有 SSIM、格式或二次 checker，应继续闭环验证。'});
  if(overBudget.length)findings.push({id:'blackbox-adversarial-over-budget',severity:'info',title:'存在成功但超扰动预算的候选',evidence:`over_budget=${overBudget.length}; epsilon=${epsilon??'n/a'}`,meaning:'模型侧目标可能已命中，但候选不满足当前扰动约束，不能作为最终解。'});
  if(queryBudgetExceeded)findings.push({id:'blackbox-query-budget-exceeded',severity:'info',title:'查询预算已超限',evidence:`observed_query=${maxQuery}; budget=${queryBudget}`,meaning:'当前 transcript 已超过题目声明的查询次数预算；后续策略应停止继续扩张查询。'});
  let status='gap';
  if(validSuccess.length&&!queryBudgetExceeded)status='candidate';
  else if(candidates.length)status='partial';
  return{
    schema:'newcyber.ai-blackbox-adversarial-transcript.v1',status,
    rows:rows.length,usable:candidates.length,norm,epsilon,queryBudget,maxObservedQuery:maxQuery,queryBudgetExceeded,
    summary:{successful:successful.length,validSuccess:validSuccess.length,overBudget:overBudget.length},
    bestCandidate:best,shortlist:candidates.slice(0,32),findings,
    nextActions:status==='candidate'?["把 bestCandidate 对应原始工件交给 challenge verifier/scorer；若有 SSIM/格式/像素范围等额外约束，必须全部满足后再升级 solved。"]:candidates.length?["优先保留距离预算内、目标分数更高的候选；若只有 label-only oracle，按当前最接近边界的候选继续受控搜索。","若题目只有远端 oracle URL 而没有授权会话/本地容器，本模块不会自行发起网络查询。"]:["提供已有 query transcript，至少包含 prediction/success/objective/distance 中一种可判定信号。"],
    notes:['本模块只分析已有的本地/授权 query transcript，不自行访问远端服务。','candidate 表示满足当前可见模型/预算约束，不代表最终 checker 已通过。']
  };
}

module.exports={num,bool,vector,distance,rowDistance,rowObjective,rowSuccess,analyzeBlackboxAdversarialTranscript};
