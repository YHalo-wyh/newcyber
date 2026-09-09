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
  if (input && typeof input==='object') {
    if (Array.isArray(input)) return input;
    if (Array.isArray(input.rows)) return input.rows;
  }
  const text=String(input||'').trim();
  if (!text) throw new Error('请输入成员/非成员查询结果');
  if (/^[\[{]/.test(text)) {
    const parsed=JSON.parse(text);
    return Array.isArray(parsed) ? parsed : parsed.rows || [];
  }
  const lines=text.split(/\r?\n/).filter((x)=>x.trim());
  if (lines.length<2) throw new Error('CSV 至少需要表头和一行数据');
  const delimiter=(lines[0].match(/\t/g)||[]).length > (lines[0].match(/,/g)||[]).length ? '\t' : ',';
  const headers=splitCsvLine(lines[0],delimiter).map((x)=>x.trim());
  return lines.slice(1).map((line)=>{
    const values=splitCsvLine(line,delimiter);
    const row={};
    headers.forEach((h,i)=>{ row[h]=values[i] ?? ''; });
    return row;
  });
}

function boolLabel(value) {
  if (typeof value==='boolean') return value;
  const text=String(value??'').trim().toLowerCase();
  if (['1','true','member','train','in','yes'].includes(text)) return true;
  if (['0','false','nonmember','non-member','test','out','no'].includes(text)) return false;
  return null;
}

function numeric(value) {
  const n=Number(value);
  return Number.isFinite(n) ? n : null;
}

function rankAuc(items, higherMeansMember=true) {
  const rows=items.filter((x)=>x.member!=null && Number.isFinite(x.value));
  const pos=rows.filter((x)=>x.member).length;
  const neg=rows.length-pos;
  if (!pos || !neg) return null;
  const sorted=[...rows].sort((a,b)=>a.value-b.value);
  let rank=1; let posRankSum=0;
  for (let i=0;i<sorted.length;) {
    let j=i+1;
    while (j<sorted.length && Math.abs(sorted[j].value-sorted[i].value)<=1e-15) j+=1;
    const avgRank=(rank + (rank + (j-i) - 1))/2;
    for (let k=i;k<j;k+=1) if (sorted[k].member) posRankSum+=avgRank;
    rank += j-i; i=j;
  }
  let auc=(posRankSum - pos*(pos+1)/2)/(pos*neg);
  if (!higherMeansMember) auc=1-auc;
  return auc;
}

function confusionAtThreshold(rows,threshold,higherMeansMember) {
  let tp=0; let tn=0; let fp=0; let fn=0;
  for (const row of rows) {
    const predicted=higherMeansMember ? row.value>=threshold : row.value<=threshold;
    if (row.member && predicted) tp+=1;
    else if (row.member) fn+=1;
    else if (predicted) fp+=1;
    else tn+=1;
  }
  const pos=tp+fn; const neg=tn+fp;
  return {threshold,tp,tn,fp,fn,tpr:pos?tp/pos:0,fpr:neg?fp/neg:0,balancedAccuracy:pos&&neg?((tp/pos)+(tn/neg))/2:null};
}

function thresholdCandidates(rows) {
  const values=[...new Set(rows.map((x)=>x.value))].sort((a,b)=>a-b);
  if (!values.length) return [];
  const out=[values[0]-Math.max(1,Math.abs(values[0]))*1e-12];
  for (let i=0;i<values.length-1;i+=1) out.push((values[i]+values[i+1])/2);
  out.push(values[values.length-1]+Math.max(1,Math.abs(values[values.length-1]))*1e-12);
  return out;
}

function bestThreshold(items, higherMeansMember=true) {
  const rows=items.filter((x)=>x.member!=null && Number.isFinite(x.value));
  const pos=rows.filter((x)=>x.member).length;
  const neg=rows.length-pos;
  if (!pos || !neg) return null;
  let best=null;
  for (const threshold of thresholdCandidates(rows)) {
    const item=confusionAtThreshold(rows,threshold,higherMeansMember);
    if (!best || item.balancedAccuracy>best.balancedAccuracy+1e-15 || (Math.abs(item.balancedAccuracy-best.balancedAccuracy)<=1e-15 && Math.abs(threshold)<Math.abs(best.threshold))) best=item;
  }
  return best;
}

function tprAtFpr(items,higherMeansMember=true,targetFpr=0.1) {
  const rows=items.filter((x)=>x.member!=null && Number.isFinite(x.value));
  const pos=rows.filter((x)=>x.member).length;
  const neg=rows.length-pos;
  if (!pos || !neg) return null;
  const limit=Math.max(0,Math.min(1,Number(targetFpr)));
  let best=null;
  for (const threshold of thresholdCandidates(rows)) {
    const item=confusionAtThreshold(rows,threshold,higherMeansMember);
    if (item.fpr>limit+1e-15) continue;
    if (!best || item.tpr>best.tpr+1e-15 || (Math.abs(item.tpr-best.tpr)<=1e-15 && item.fpr<best.fpr-1e-15)) best=item;
  }
  return best ? {...best,targetFpr:limit} : null;
}

function membershipAdvantage(items,higherMeansMember=true) {
  const rows=items.filter((x)=>x.member!=null && Number.isFinite(x.value));
  const pos=rows.filter((x)=>x.member).length;
  const neg=rows.length-pos;
  if (!pos || !neg) return null;
  let best=null;
  for (const threshold of thresholdCandidates(rows)) {
    const item=confusionAtThreshold(rows,threshold,higherMeansMember);
    const advantage=item.tpr-item.fpr;
    if (!best || advantage>best.advantage+1e-15) best={...item,advantage};
  }
  return best;
}

function mean(values) {
  return values.length ? values.reduce((a,b)=>a+b,0)/values.length : null;
}

function summarizeSignal(rows, aliases, higherMeansMember, id) {
  const key=aliases.find((name)=>rows.some((row)=>numeric(row[name])!=null));
  if (!key) return null;
  const items=rows.map((row)=>({ member:boolLabel(row.member ?? row.is_member ?? row.split ?? row.membership), value:numeric(row[key]) }));
  const usable=items.filter((x)=>x.member!=null && x.value!=null);
  const members=usable.filter((x)=>x.member).map((x)=>x.value);
  const nonmembers=usable.filter((x)=>!x.member).map((x)=>x.value);
  if (!members.length || !nonmembers.length) return { id,key,usable:usable.length,auc:null,threshold:null,tprAtFpr10:null,membershipAdvantage:null };
  const lowFpr=tprAtFpr(usable,higherMeansMember,0.1);
  const advantage=membershipAdvantage(usable,higherMeansMember);
  return {
    id,
    key,
    direction:higherMeansMember?'higher-member':'lower-member',
    usable:usable.length,
    memberMean:mean(members),
    nonMemberMean:mean(nonmembers),
    gap:mean(members)-mean(nonmembers),
    auc:rankAuc(usable,higherMeansMember),
    threshold:bestThreshold(usable,higherMeansMember),
    tprAtFpr10:lowFpr,
    membershipAdvantage:advantage
  };
}

function riskLevel(signals) {
  const auc=Math.max(...signals.map((x)=>x?.auc).filter(Number.isFinite),0.5);
  const lowFpr=Math.max(...signals.map((x)=>x?.tprAtFpr10?.tpr).filter(Number.isFinite),0);
  if (auc>=0.85 || lowFpr>=0.5) return 'high';
  if (auc>=0.7 || lowFpr>=0.25) return 'medium';
  if (auc>=0.6 || lowFpr>0) return 'low';
  return 'weak';
}

function analyzePrivacyTranscript(input) {
  const rows=parseRows(input);
  const labeled=rows.filter((row)=>boolLabel(row.member ?? row.is_member ?? row.split ?? row.membership)!=null).length;
  const signals=[
    summarizeSignal(rows,['confidence','max_confidence','prob','score'],true,'confidence'),
    summarizeSignal(rows,['loss','nll','cross_entropy'],false,'loss'),
    summarizeSignal(rows,['entropy'],false,'entropy')
  ].filter(Boolean);
  const level=riskLevel(signals);
  const findings=[];
  const strongest=[...signals].filter((x)=>Number.isFinite(x.auc)).sort((a,b)=>(b.tprAtFpr10?.tpr||0)-(a.tprAtFpr10?.tpr||0)||b.auc-a.auc)[0] || null;
  if (strongest?.auc>=0.7 || strongest?.tprAtFpr10?.tpr>=0.25) findings.push({
    id:'membership-separation',
    severity:strongest.auc>=0.85||strongest?.tprAtFpr10?.tpr>=0.5?'high':'medium',
    evidence:`signal=${strongest.id} auc=${strongest.auc?.toFixed(4)??'n/a'} tpr@0.1fpr=${strongest.tprAtFpr10?.tpr?.toFixed(4)??'n/a'}`,
    meaning:'成员/非成员在该信号上存在可量化分离；低 FPR operating point 更接近竞赛型 MIA 评分，但仍需独立 holdout/reference 分布复核。'
  });
  if (labeled===0) findings.push({ id:'privacy-groundtruth-missing', severity:'info', evidence:'member labels absent', meaning:'没有成员/非成员真值，只能整理模型输出分布，无法计算真实 MIA 区分能力。' });
  return {
    rows:rows.length,
    labeledRows:labeled,
    signals,
    strongestSignal:strongest,
    competitionMetrics:strongest?{
      auc:strongest.auc,
      tprAtFpr10:strongest.tprAtFpr10?.tpr??null,
      realizedFpr:strongest.tprAtFpr10?.fpr??null,
      lowFprThreshold:strongest.tprAtFpr10?.threshold??null,
      membershipAdvantage:strongest.membershipAdvantage?.advantage??null
    }:null,
    privacyRisk:level,
    findings,
    notes:[
      'AUC 与阈值只衡量当前 transcript 的成员区分能力；不要把它解释为训练数据泄露的绝对概率。',
      'TPR@0.1FPR 是竞赛型低误报 operating point；样本过少时只能作为本地回归指标，不应夸大统计显著性。',
      '比赛若给 shadow/reference model 或多次查询结果，应按相同 preprocessing 生成独立参考分布再比较。'
    ]
  };
}

function buildPrivacyHarness(input={}) {
  const data=input && typeof input==='object' ? input : {};
  const signal=String(data.signal||'loss');
  const privacyMeter=`# Privacy Meter integration plan\n# Project: privacytrustlab/ml_privacy_meter\n# 1. Implement the target model/dataset wrappers from the challenge code.\n# 2. Keep the challenge preprocessing identical.\n# 3. Configure membership inference with the requested signal (${signal}).\n# 4. Export per-record attack scores, then feed them back to NewCyber's transcript auditor for AUC/TPR@0.1FPR comparison.\n`;
  const art=`# ART membership-inference harness sketch\nfrom art.attacks.inference.membership_inference import MembershipInferenceBlackBox\n\n# classifier = ...  # wrap the trusted challenge model with an ART estimator\n# attack = MembershipInferenceBlackBox(classifier, input_type='${signal==='loss'?'loss':'prediction'}')\n# attack.fit(x_member, y_member, x_nonmember, y_nonmember)\n# inferred = attack.infer(x_query, y_query)\n`;
  return {
    harnesses:[
      { backend:'Privacy Meter', project:'privacytrustlab/ml_privacy_meter', text:privacyMeter },
      { backend:'ART', project:'Trusted-AI/adversarial-robustness-toolbox', text:art }
    ],
    notes:['NewCyber 负责 transcript 归一化、AUC/低 FPR operating point 和结果解释；模型 wrapper 仍按赛题实际代码填写。']
  };
}

module.exports={ splitCsvLine, parseRows, rankAuc, bestThreshold, tprAtFpr, membershipAdvantage, analyzePrivacyTranscript, buildPrivacyHarness };
