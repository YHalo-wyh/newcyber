'use strict';

const {parseRows}=require('./ai_privacy');

function normalize(value){return String(value??'').trim();}
function pickKey(rows,names){
  const keys=new Map();for(const row of rows.slice(0,200))for(const key of Object.keys(row||{}))keys.set(key.toLowerCase(),key);
  for(const name of names){const key=keys.get(name.toLowerCase());if(key)return key;}return null;
}
function tokenize(value){
  return [...new Set((normalize(value).toLowerCase().match(/[\p{L}\p{N}_-]{2,48}/gu)||[]).filter((x)=>!/^\d{5,}$/.test(x)))].slice(0,128);
}
function candidateFeatures(row,labelKey){
  const out=[];
  for(const [key,raw] of Object.entries(row||{})){
    if(key===labelKey||/^__/.test(key))continue;
    const value=normalize(raw);if(!value||value.length>4096)continue;
    if(/(?:text|content|prompt|input|sentence|caption|message|comment|name|trigger|pattern|patch|token)/i.test(key)){
      for(const token of tokenize(value))out.push(`${key}:token=${token}`);
    }else if(value.length<=64&&!/^(?:-?\d+(?:\.\d+)?)$/.test(value))out.push(`${key}:value=${value.toLowerCase()}`);
  }
  return [...new Set(out)].slice(0,256);
}

function analyzeBackdoorTriggerAssociations(input={}){
  const rows=parseRows(input).slice(0,50000);
  const labelKey=pickKey(rows,['target_label','label','class','y','ground_truth','true_label']);
  if(!labelKey)return{schema:'newcyber.ai-backdoor-trigger-search.v1',status:'gap',reason:'未找到 label/class/target_label 列',rows:rows.length,candidates:[],findings:[]};
  const labelCounts=new Map();const featureCounts=new Map();
  for(const row of rows){
    const label=normalize(row[labelKey]);if(!label)continue;
    labelCounts.set(label,(labelCounts.get(label)||0)+1);
    for(const feature of candidateFeatures(row,labelKey)){
      let stat=featureCounts.get(feature);if(!stat){stat={support:0,labels:new Map()};featureCounts.set(feature,stat);}
      stat.support++;stat.labels.set(label,(stat.labels.get(label)||0)+1);
    }
  }
  const total=[...labelCounts.values()].reduce((a,b)=>a+b,0);
  const candidates=[];
  for(const [feature,stat] of featureCounts){
    if(stat.support<3||!total)continue;
    const prevalence=stat.support/total;if(prevalence>0.25)continue;
    const [target,targetSupport]=[...stat.labels.entries()].sort((a,b)=>b[1]-a[1])[0]||[];if(!target)continue;
    const purity=targetSupport/stat.support;const base=(labelCounts.get(target)||0)/total;const lift=base?purity/base:null;
    if(purity<0.75||lift===null||lift<1.8)continue;
    candidates.push({feature,support:stat.support,prevalence,targetLabel:target,targetSupport,purity,lift,score:purity*Math.log2(1+stat.support)*Math.min(lift,8)});
  }
  candidates.sort((a,b)=>b.score-a.score||b.support-a.support||a.feature.localeCompare(b.feature));
  const top=candidates.slice(0,80);
  const strong=top.filter((x)=>x.support>=5&&x.purity>=0.9&&x.lift>=2.5);
  const findings=[];
  if(strong.length)findings.push({id:'backdoor-trigger-association-candidate',severity:'medium',title:'稀有特征与单一标签存在强关联',evidence:strong.slice(0,5).map((x)=>`${x.feature} -> ${x.targetLabel} support=${x.support} purity=${x.purity.toFixed(3)} lift=${x.lift.toFixed(2)}`).join('; '),meaning:'稀有 token/类别特征对某一标签高度集中，符合 trigger/poison 候选形态；必须通过移除特征、位置/纹理对照或 clean/triggered 推理验证，不能仅凭共现认定后门。'});
  return{
    schema:'newcyber.ai-backdoor-trigger-search.v1',status:top.length?'candidate':'no-strong-association',rows:rows.length,labelKey,
    labels:Object.fromEntries(labelCounts),candidates:top,findings,
    nextActions:top.length?[
      '优先把高 purity/high lift 且低 prevalence 的候选作为触发器假设，构造中性对照而不是直接认定后门。',
      '对候选做 ablation：移除/替换 token、改变位置或样式，比较目标 ASR 与 control target rate。',
      '把验证结果交给 ai-backdoor-behavior，只有 trigger effect 明显高于 control 才升级证据。'
    ]:['未发现达到阈值的稀有标签关联；继续检查图像 patch、频域或模型权重级异常。'],
    notes:['本模块只做防御性关联搜索，不生成投毒载荷。','support<3、过高 prevalence、低 purity 或低 lift 的特征会被过滤，避免把普通类别词误判成 trigger。']
  };
}

module.exports={pickKey,tokenize,candidateFeatures,analyzeBackdoorTriggerAssociations};
