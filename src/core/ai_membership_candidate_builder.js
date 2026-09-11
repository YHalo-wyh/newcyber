'use strict';

const {parseRows,rankAuc,bestThreshold,tprAtFpr}=require('./ai_privacy');

function text(value){return String(value??'').trim();}
function num(value){if(value===null||value===undefined||value==='')return null;const n=Number(value);return Number.isFinite(n)?n:null;}
function boolLabel(value){
  if(typeof value==='boolean')return value;
  const v=text(value).toLowerCase();
  if(['1','true','member','train','in','yes'].includes(v))return true;
  if(['0','false','nonmember','non-member','test','out','no'].includes(v))return false;
  return null;
}
function keyMap(row){return new Map(Object.keys(row||{}).map((k)=>[k.toLowerCase(),k]));}
function first(row,names){const map=keyMap(row);for(const name of names){const k=map.get(name.toLowerCase());if(k!=null&&row[k]!==''&&row[k]!=null)return row[k];}return null;}
function idOf(row,index){return text(first(row,['id','sample_id','record_id','index','uid','candidate_id','name','file','filename']))||String(index+1);}

const SIGNALS=Object.freeze([
  {id:'loss',aliases:['loss','nll','cross_entropy'],higherMember:false},
  {id:'entropy',aliases:['entropy'],higherMember:false},
  {id:'confidence',aliases:['confidence','max_confidence','prob','probability','score'],higherMember:true},
  {id:'margin',aliases:['margin','top1_margin','confidence_margin'],higherMember:true}
]);

function signalValue(row,spec){return num(first(row,spec.aliases));}
function chooseCalibrationSignal(rows,targetFpr=0.1){
  const candidates=[];
  for(const spec of SIGNALS){
    const items=rows.map((row)=>({member:boolLabel(first(row,['member','is_member','membership','split'])),value:signalValue(row,spec)})).filter((x)=>x.member!=null&&x.value!=null);
    const pos=items.filter((x)=>x.member).length,neg=items.length-pos;if(!pos||!neg)continue;
    const auc=rankAuc(items,spec.higherMember);const low=tprAtFpr(items,spec.higherMember,targetFpr);const balanced=bestThreshold(items,spec.higherMember);
    const quality=(low?.tpr??0)*4+(Number.isFinite(auc)?auc:0)+(balanced?.balancedAccuracy??0)*0.5;
    candidates.push({...spec,usable:items.length,members:pos,nonmembers:neg,auc,lowFpr:low,balanced,quality});
  }
  candidates.sort((a,b)=>b.quality-a.quality||(b.lowFpr?.tpr??0)-(a.lowFpr?.tpr??0)||(b.auc??0)-(a.auc??0)||a.id.localeCompare(b.id));
  return{best:candidates[0]||null,candidates};
}
function confidenceFromDistance(value,threshold,spread,higherMember){
  if(!Number.isFinite(value)||!Number.isFinite(threshold))return null;
  const denom=Math.max(Math.abs(spread)||0,1e-9);const signed=(higherMember?1:-1)*(value-threshold)/denom;
  return 1/(1+Math.exp(-Math.max(-30,Math.min(30,signed))));
}
function calibrationSpread(rows,spec,threshold){
  const values=rows.map((row)=>signalValue(row,spec)).filter(Number.isFinite).map((x)=>Math.abs(x-threshold)).sort((a,b)=>a-b);
  if(!values.length)return 1;return values[Math.floor(values.length*0.5)]||values.reduce((a,b)=>a+b,0)/values.length||1;
}

function buildMembershipCandidates(input={}){
  const data=input&&typeof input==='object'&&!Array.isArray(input)?input:{};
  const calibration=parseRows(data.calibration??data.reference??data.shadow??data.labeled??[]).slice(0,100000);
  const query=parseRows(data.query??data.challenge??data.unlabeled??data.rows??[]).slice(0,100000);
  const targetFpr=Math.max(0,Math.min(0.5,num(data.targetFpr??data.target_fpr)??0.1));
  if(!calibration.length)return{schema:'newcyber.ai-membership-candidates.v1',status:'gap',reason:'缺少带 member/non-member 真值的 calibration/reference 数据',candidates:[],findings:[]};
  if(!query.length)return{schema:'newcyber.ai-membership-candidates.v1',status:'gap',reason:'缺少待判定 query/challenge 数据',candidates:[],findings:[]};
  const selection=chooseCalibrationSignal(calibration,targetFpr);const best=selection.best;
  if(!best||!best.lowFpr||!Number.isFinite(best.lowFpr.threshold))return{schema:'newcyber.ai-membership-candidates.v1',status:'gap',reason:'calibration 数据没有同时包含可用信号与正/负成员真值',signalCandidates:selection.candidates,candidates:[],findings:[]};
  const threshold=best.lowFpr.threshold;const spread=calibrationSpread(calibration,best,threshold);
  const candidates=[];let usable=0;
  for(let index=0;index<query.length;index++){
    const value=signalValue(query[index],best);if(value==null)continue;usable++;
    const member=best.higherMember?value>=threshold:value<=threshold;
    const confidence=confidenceFromDistance(value,threshold,spread,best.higherMember);
    candidates.push({id:idOf(query[index],index),value,member,confidence,margin:(best.higherMember?1:-1)*(value-threshold)});
  }
  candidates.sort((a,b)=>Number(b.member)-Number(a.member)||(b.confidence??0)-(a.confidence??0)||String(a.id).localeCompare(String(b.id)));
  const findings=[];
  if(best.auc>=0.7||best.lowFpr.tpr>=0.25)findings.push({id:'membership-calibration-separation',severity:best.auc>=0.85||best.lowFpr.tpr>=0.5?'high':'medium',title:'Calibration 数据存在可用于候选生成的成员分离信号',evidence:`signal=${best.id}; auc=${best.auc?.toFixed(4)}; tpr@${targetFpr}fpr=${best.lowFpr.tpr?.toFixed(4)}; threshold=${threshold}`,meaning:'阈值只由带真值的 calibration/reference 子集确定，再冻结应用到未标注 query；未使用 query 真值调参。'});
  const memberCandidates=candidates.filter((x)=>x.member);
  return{
    schema:'newcyber.ai-membership-candidates.v1',status:usable?'candidate':'gap',
    calibrationRows:calibration.length,queryRows:query.length,usableQueryRows:usable,targetFpr,
    signal:{id:best.id,higherMember:best.higherMember,auc:best.auc,threshold,tpr:best.lowFpr.tpr,realizedFpr:best.lowFpr.fpr,spread},
    memberCandidateCount:memberCandidates.length,candidates:candidates.slice(0,100000),memberIds:memberCandidates.map((x)=>x.id),findings,
    nextActions:usable?['按题目 submission schema 输出 member confidence/ID；若 verifier/scorer 给出 TPR@FPR 约束，用独立 holdout 复算，不要在 challenge 真值上重新调 threshold。']:['确认 query 表包含 calibration 选中的同名 signal 列。'],
    notes:['为了避免 leaderboard/真值泄漏导致过拟合，threshold 只允许从显式 calibration/reference 真值计算。','candidate 不是隐私泄漏的绝对证明；它表示当前公开信号和 operating point 下的成员候选。']
  };
}

module.exports={SIGNALS,boolLabel,idOf,chooseCalibrationSignal,confidenceFromDistance,buildMembershipCandidates};
