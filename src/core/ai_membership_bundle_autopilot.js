'use strict';

const {SIGNALS,boolLabel,buildMembershipCandidates}=require('./ai_membership_candidate_builder');

const MEMBER_ALIASES=['member','is_member','membership','split','membership_label','in_training','train_member'];
const ID_ALIASES=['id','sample_id','record_id','index','uid','candidate_id','name','file','filename'];
const MAX_ROWS=100000;
const MAX_FILES=96;

function text(value){return String(value??'').trim();}
function keyMap(row){return new Map(Object.keys(row||{}).map((key)=>[key.toLowerCase(),key]));}
function first(row,names){const map=keyMap(row);for(const name of names){const key=map.get(String(name).toLowerCase());if(key!=null&&row[key]!==''&&row[key]!=null)return row[key];}return null;}
function numeric(value){if(value===null||value===undefined||value==='')return null;const n=Number(value);return Number.isFinite(n)?n:null;}
function memberOf(row){return boolLabel(first(row,MEMBER_ALIASES));}
function idOf(row,index){return text(first(row,ID_ALIASES))||String(index+1);}

function splitDelimitedLine(line,delimiter){
  const out=[];let cell='';let quoted=false;
  for(let index=0;index<line.length;index+=1){
    const ch=line[index];
    if(ch==='"'){
      if(quoted&&line[index+1]==='"'){cell+='"';index+=1;continue;}
      quoted=!quoted;continue;
    }
    if(ch===delimiter&&!quoted){out.push(cell.trim());cell='';continue;}
    cell+=ch;
  }
  out.push(cell.trim());return out;
}
function parseDelimited(raw,delimiter){
  const lines=String(raw||'').split(/\r?\n/).filter((line)=>line.trim()).slice(0,MAX_ROWS+1);if(lines.length<2)return[];
  const headers=splitDelimitedLine(lines.shift(),delimiter).map((x)=>x.trim());if(!headers.length)return[];
  return lines.map((line)=>{const values=splitDelimitedLine(line,delimiter);const row={};headers.forEach((header,index)=>{row[header]=values[index]??'';});return row;});
}
function objectRows(value){return Array.isArray(value)&&value.length&&value.every((row)=>row&&typeof row==='object'&&!Array.isArray(row));}
function datasetsFromJson(path,root){
  const out=[];const seen=new Set();
  const add=(name,rows)=>{if(!objectRows(rows))return;const key=`${name}:${rows.length}`;if(seen.has(key))return;seen.add(key);out.push({path,name,rows:rows.slice(0,MAX_ROWS)});};
  if(Array.isArray(root)){add('root',root);return out;}
  if(!root||typeof root!=='object')return out;
  for(const name of ['calibration','reference','shadow','labeled','train','query','challenge','unlabeled','test','eval','rows','data','records','samples'])add(name,root[name]);
  if(!out.length){
    for(const [name,value] of Object.entries(root)){if(objectRows(value))add(name,value);if(out.length>=8)break;}
  }
  return out;
}
function datasetsFromFile(file){
  const path=text(file?.path||file?.file||'input');const raw=String(file?.text??file?.content??'').trim();if(!raw)return[];
  if(/^[\[{]/.test(raw)){
    try{const json=JSON.parse(raw);const rows=datasetsFromJson(path,json);if(rows.length)return rows;}catch{}
  }
  const lines=raw.split(/\r?\n/).filter(Boolean);
  if(lines.length>=2&&lines.slice(0,Math.min(lines.length,100)).every((line)=>/^\s*\{/.test(line))){
    const rows=[];for(const line of lines.slice(0,MAX_ROWS)){try{const value=JSON.parse(line);if(value&&typeof value==='object'&&!Array.isArray(value))rows.push(value);}catch{}}
    if(rows.length)return[{path,name:'jsonl',rows}];
  }
  const firstLine=lines[0]||'';const delimiter=firstLine.includes('\t')?'\t':firstLine.includes(',')?',':null;
  if(delimiter){const rows=parseDelimited(raw,delimiter);if(rows.length)return[{path,name:delimiter==='\t'?'tsv':'csv',rows}];}
  return[];
}
function signalCoverage(rows){
  const coverage={};
  for(const spec of SIGNALS){let count=0;for(const row of rows){if(numeric(first(row,spec.aliases))!=null)count+=1;}if(count)coverage[spec.id]=count;}
  return coverage;
}
function datasetMeta(dataset){
  const rows=dataset.rows||[];let members=0,nonmembers=0,unlabeled=0;
  for(const row of rows){const label=memberOf(row);if(label===true)members+=1;else if(label===false)nonmembers+=1;else unlabeled+=1;}
  const coverage=signalCoverage(rows);const signalIds=Object.keys(coverage).filter((id)=>coverage[id]>=Math.min(3,Math.max(1,Math.ceil(rows.length*0.2))));
  const name=`${dataset.path}#${dataset.name}`;
  return{...dataset,name,members,nonmembers,unlabeled,coverage,signalIds,calibrationReady:members>0&&nonmembers>0&&signalIds.length>0,queryReady:unlabeled>0&&signalIds.length>0};
}
function roleBonus(meta,role){
  const value=`${meta.path} ${meta.name}`.toLowerCase();
  if(role==='calibration')return/(?:calib|reference|shadow|labeled|member|train)/.test(value)?0.5:0;
  return/(?:query|challenge|unlabeled|test|eval|target|submit)/.test(value)?0.5:0;
}
function specById(id){return SIGNALS.find((item)=>item.id===id)||null;}
function projectRows(rows,spec,withLabel){
  return rows.map((row,index)=>{
    const out={id:idOf(row,index)};const value=numeric(first(row,spec.aliases));if(value!=null)out[spec.id]=value;
    if(withLabel){const label=memberOf(row);if(label!=null)out.member=label;}
    return out;
  }).filter((row)=>numeric(row[spec.id])!=null&&(withLabel?typeof row.member==='boolean':true));
}
function candidatePairs(datasets,targetFpr=0.1){
  const metas=datasets.map(datasetMeta);const calibrations=metas.filter((x)=>x.calibrationReady);const queries=metas.filter((x)=>x.queryReady);const pairs=[];
  for(const calibration of calibrations){
    for(const query of queries){
      const shared=calibration.signalIds.filter((id)=>query.signalIds.includes(id));
      for(const signalId of shared){
        const spec=specById(signalId);if(!spec)continue;
        const calibrationRows=projectRows(calibration.rows,spec,true);const queryRows=projectRows(query.rows.filter((row)=>memberOf(row)==null),spec,false);if(!calibrationRows.length||!queryRows.length)continue;
        let result;try{result=buildMembershipCandidates({calibration:calibrationRows,query:queryRows,targetFpr});}catch{continue;}
        if(result.status!=='candidate'||!result.usableQueryRows)continue;
        const auc=Number(result.signal?.auc)||0;const tpr=Number(result.signal?.tpr)||0;const sizeBonus=Math.min(0.7,Math.log10(1+calibrationRows.length+queryRows.length)/5);
        const score=auc*2+tpr*4+sizeBonus+roleBonus(calibration,'calibration')+roleBonus(query,'query')+(calibration.path===query.path?0.1:0);
        pairs.push({score,signalId,calibration:{path:calibration.path,name:calibration.name,rows:calibrationRows.length},query:{path:query.path,name:query.name,rows:queryRows.length},result});
      }
    }
  }
  pairs.sort((a,b)=>b.score-a.score||(b.result.signal?.auc??0)-(a.result.signal?.auc??0)||(b.result.usableQueryRows??0)-(a.result.usableQueryRows??0)||`${a.calibration.path}:${a.query.path}`.localeCompare(`${b.calibration.path}:${b.query.path}`));
  return{metas,pairs};
}
function membershipLike(files,datasets){
  if(datasets.some((item)=>item.members>0||item.nonmembers>0))return true;
  return files.some((file)=>/(?:membership|member|nonmember|non-member|mia|privacy attack)/i.test(`${file?.path||''}\n${String(file?.text||'').slice(0,12000)}`));
}
function compactDataset(meta){return{path:meta.path,name:meta.name,rows:meta.rows.length,members:meta.members,nonmembers:meta.nonmembers,unlabeled:meta.unlabeled,signals:meta.signalIds};}

function analyzeMembershipBundle(files=[],options={}){
  const input=Array.isArray(files)?files.slice(0,MAX_FILES):[];const datasets=input.flatMap(datasetsFromFile).slice(0,MAX_FILES*4).map(datasetMeta);
  if(!datasets.length)return{schema:'newcyber.ai-membership-bundle-autopilot.v1',status:'not-detected',summary:{files:input.length,datasets:0,pairs:0},datasets:[],selection:null,result:null,findings:[],next:null};
  const targetFpr=Math.max(0,Math.min(0.5,Number(options.targetFpr??0.1)||0.1));
  const prepared=candidatePairs(datasets,targetFpr);const metas=prepared.metas;const pairs=prepared.pairs;const detected=membershipLike(input,metas);
  if(!pairs.length){
    if(!detected)return{schema:'newcyber.ai-membership-bundle-autopilot.v1',status:'not-detected',summary:{files:input.length,datasets:metas.length,pairs:0},datasets:metas.map(compactDataset),selection:null,result:null,findings:[],next:null};
    const hasCalibration=metas.some((x)=>x.calibrationReady);const hasQuery=metas.some((x)=>x.queryReady);
    const reason=!hasCalibration?'缺少同时含 member/non-member 真值和 loss/confidence/entropy/margin 信号的 calibration/reference 数据':!hasQuery?'缺少未标注 query/challenge 数据，或 query 没有与 calibration 同名的可用信号列':'calibration 与 query 没有共同可判定信号';
    return{schema:'newcyber.ai-membership-bundle-autopilot.v1',status:'gap',reason,summary:{files:input.length,datasets:metas.length,pairs:0},datasets:metas.map(compactDataset),selection:null,result:null,findings:[],next:reason};
  }
  const best=pairs[0],second=pairs[1]||null;const ambiguous=Boolean(second&&Math.abs(best.score-second.score)<0.08&&(`${best.calibration.path}#${best.calibration.name}|${best.query.path}#${best.query.name}|${best.signalId}`!==`${second.calibration.path}#${second.calibration.name}|${second.query.path}#${second.query.name}|${second.signalId}`));
  if(ambiguous){
    return{schema:'newcyber.ai-membership-bundle-autopilot.v1',status:'ambiguous',reason:'发现多个几乎等价的 calibration/query 配对，自动链停止猜测。',summary:{files:input.length,datasets:metas.length,pairs:pairs.length},datasets:metas.map(compactDataset),selection:null,alternatives:pairs.slice(0,6).map((x)=>({score:x.score,signal:x.signalId,calibration:x.calibration,query:x.query})),result:null,findings:[],next:'提供题目说明、submission sample 或把 calibration/query 文件名标清后重新丢入。'};
  }
  const ids=best.result.memberIds||[];const payload=JSON.stringify(ids);const preview=ids.length<=16?payload:`${ids.length} 个 member 候选 · ${JSON.stringify(ids.slice(0,12))} …`;
  const finding={id:'membership-bundle-candidate',severity:(best.result.signal?.auc??0)>=0.85?'high':'medium',title:'自动关联 calibration/query 并生成 Membership 候选',evidence:`signal=${best.signalId}; calibration=${best.calibration.path}#${best.calibration.name}; query=${best.query.path}#${best.query.name}; auc=${Number(best.result.signal?.auc||0).toFixed(4)}; tpr@fpr=${Number(best.result.signal?.tpr||0).toFixed(4)}; members=${ids.length}`,meaning:'阈值只从带真值 calibration/reference 数据计算，并冻结应用到未标注 query。仍需题目 submission schema / scorer / verifier 才能升级为 solved。'};
  return{
    schema:'newcyber.ai-membership-bundle-autopilot.v1',status:'candidate',
    summary:{files:input.length,datasets:metas.length,pairs:pairs.length,memberCandidates:ids.length,queryRows:best.result.usableQueryRows},
    datasets:metas.map(compactDataset),
    selection:{score:best.score,signal:best.signalId,calibration:best.calibration,query:best.query,threshold:best.result.signal?.threshold,targetFpr:best.result.targetFpr,auc:best.result.signal?.auc,tpr:best.result.signal?.tpr,realizedFpr:best.result.signal?.realizedFpr},
    result:{kind:'membership-id-list',verified:false,value:payload,displayValue:preview,payload,memberIds:ids,source:`${best.calibration.path} + ${best.query.path}`},
    candidates:best.result,findings:[finding],
    next:'已生成 member ID 候选；补 checker/verifier、submission sample 或评分规则后自动按题目格式封装并验证。',
    notes:['不使用 challenge 真值重新调 threshold。','多个近似等价数据配对时会停在 ambiguous，不根据文件顺序猜测。']
  };
}

module.exports={MEMBER_ALIASES,splitDelimitedLine,parseDelimited,datasetsFromFile,datasetMeta,candidatePairs,analyzeMembershipBundle};
