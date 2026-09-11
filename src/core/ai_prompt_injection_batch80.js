'use strict';

const legacy=require('./ai_prompt_injection');
const arsenal=require('./ai_prompt_attack_arsenal');

function parseOptions(input){
  if(input&&typeof input==='object')return input;
  const text=String(input||'').trim();
  if(!text)return{};
  try{return JSON.parse(text);}catch{return{response:text};}
}

function buildPromptInjectionSuite(input={}){
  const data=parseOptions(input);
  const base=legacy.buildPromptInjectionSuite({...data,competitionOnly:false,pack:null,ids:null,category:null});
  const extra=arsenal.buildPromptAttackArsenal({
    marker:data.marker||legacy.DEFAULT_MARKER,
    canary:data.canary||legacy.DEFAULT_CANARY,
    tool:data.tool||legacy.DEFAULT_TOOL,
    limit:512
  });
  const category=data.category?String(data.category):null;
  const ids=Array.isArray(data.ids)?new Set(data.ids.map(String)):null;
  const competitionOnly=data.competitionOnly===true||String(data.pack||'').toLowerCase()==='competition';
  const templates=[...base.templates,...extra.templates]
    .filter((item)=>!category||item.category===category)
    .filter((item)=>!ids||ids.has(item.id))
    .filter((item)=>!competitionOnly||item.competition===true);
  return{
    ...base,
    schema:'newcyber.prompt-injection-suite.v2',
    templates,
    coverage:[...new Set(templates.map((x)=>x.category))],
    competitionCount:templates.filter((x)=>x.competition===true).length,
    arsenal:{seeds:extra.seeds,mutations:extra.mutations,total:extra.total,coverage:extra.coverage},
    notes:[...base.notes,`Batch80 Arsenal 已并入：${extra.seeds} 个攻击家族 × ${extra.mutations} 种表达变体，默认 ${extra.total} 条额外比赛模板。`]
  };
}

function evaluatePromptInjectionRun(input={}){
  const data=parseOptions(input);
  const result=legacy.evaluatePromptInjectionRun(data);
  if(data.templateId){
    const template=buildPromptInjectionSuite({...data,competitionOnly:false,pack:null,ids:[String(data.templateId)]}).templates[0]||null;
    if(template)result.template=template;
  }
  result.suiteSchema='newcyber.prompt-injection-suite.v2';
  return result;
}

module.exports={
  ...legacy,
  buildPromptInjectionSuite,
  evaluatePromptInjectionRun,
  buildPromptAttackArsenal:arsenal.buildPromptAttackArsenal,
  ARSENAL_SEEDS:arsenal.SEEDS,
  ARSENAL_MUTATIONS:arsenal.MUTATIONS
};
