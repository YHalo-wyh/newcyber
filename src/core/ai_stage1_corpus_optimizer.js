'use strict';

const {PUBLIC_TRAINING_SEEDS}=require('./ai_stage1_training_corpus');
const {DIRECTIONS,byDirection}=require('./ai_stage1_source_registry');

function normUrl(value){
  return String(value||'').trim().replace(/\/$/,'').toLowerCase();
}

function seedSource(seed){return normUrl(seed?.provenance?.url);}

function auditCurrentCorpusCoverage(seeds=PUBLIC_TRAINING_SEEDS,options={}){
  const minDistinctSources=Math.max(1,Number(options.minDistinctSources)||6);
  const groups=DIRECTIONS.map((direction)=>{
    const current=seeds.filter((x)=>x.direction===direction);
    const sourceUrls=new Set(current.map(seedSource).filter(Boolean));
    const catalog=byDirection(direction).slice().sort((a,b)=>(b.priority||0)-(a.priority||0));
    const matched=catalog.filter((x)=>sourceUrls.has(normUrl(x.url)));
    const missing=catalog.filter((x)=>!sourceUrls.has(normUrl(x.url)));
    const highPriorityMissing=missing.filter((x)=>(x.priority||0)>=94);
    const sourceGap=Math.max(0,minDistinctSources-sourceUrls.size);
    return {
      direction,
      currentSeeds:current.length,
      distinctCurrentSources:sourceUrls.size,
      matchedCatalogSources:matched.map((x)=>x.id),
      sourceGap,
      highPriorityMissing:highPriorityMissing.slice(0,12).map((x)=>({
        id:x.id,title:x.title,tier:x.tier,priority:x.priority,url:x.url,importMode:x.importMode
      })),
      status:sourceGap===0&&highPriorityMissing.length<=2?'healthy':sourceUrls.size>=3?'expand':'thin'
    };
  });

  const queue=groups.flatMap((group)=>group.highPriorityMissing.map((source)=>({
    direction:group.direction,
    sourceGap:group.sourceGap,
    ...source
  }))).sort((a,b)=>b.sourceGap-a.sourceGap||b.priority-a.priority||a.id.localeCompare(b.id));

  return {
    schema:'newcyber.ai-stage1-corpus-audit.v2',
    currentSeedCount:seeds.length,
    groups,
    queue,
    summary:{
      directions:DIRECTIONS.length,
      distinctCurrentSources:new Set(seeds.map(seedSource).filter(Boolean)).size,
      highPriorityMissing:queue.length,
      thinDirections:groups.filter((x)=>x.status==='thin').length,
      expandDirections:groups.filter((x)=>x.status==='expand').length
    },
    recommendation:'优先增加 upstream source diversity，再在同一 source 内做 mutation；真实赛题/官方竞赛数据的权重高于合成变体数量。'
  };
}

function buildTrainingMix(audit=auditCurrentCorpusCoverage()){
  const weights={A:0.45,B:0.35,C:0.15,synthetic:0.05};
  return {
    schema:'newcyber.ai-stage1-training-mix.v2',
    weights,
    split:{train:0.70,validation:0.15,test:0.15,groupKey:'upstream-source-or-competition'},
    requirements:{
      hardNegativeRatio:0.30,
      preserveVerifier:true,
      stripFinalAnswers:true,
      preserveProvenance:true,
      forbidUnsafeArtifactExecution:true
    },
    importQueue:audit.queue.slice(0,32)
  };
}

module.exports={auditCurrentCorpusCoverage,buildTrainingMix,normUrl};
