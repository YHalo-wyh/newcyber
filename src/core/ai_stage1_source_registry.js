'use strict';

const base=require('./ai_stage1_source_catalog');
const {AI_STAGE1_SOURCE_EXPANSION}=require('./ai_stage1_source_expansion');

const DIRECTIONS=base.DIRECTIONS;
const SOURCE_REGISTRY=Object.freeze((()=>{
  const map=new Map();
  for(const source of [...base.AI_STAGE1_SOURCE_CATALOG,...AI_STAGE1_SOURCE_EXPANSION]){
    if(!source?.id)continue;
    if(map.has(source.id))throw new Error(`duplicate AI corpus source id: ${source.id}`);
    map.set(source.id,Object.freeze({...source}));
  }
  return [...map.values()];
})());

function byDirection(direction){return SOURCE_REGISTRY.filter((source)=>source.direction===direction);}

function registryHealth(){
  const counts=Object.fromEntries(DIRECTIONS.map((direction)=>[direction,byDirection(direction).length]));
  const domestic=SOURCE_REGISTRY.filter((source)=>/(长城杯|湾区杯|羊城杯)/.test(source.title||''));
  const requestedCore=['tensortrust-data','prompt-airlines','gandalf-ignore-instructions','agentdojo','madry-mnist-challenge','madry-cifar10-challenge','nips17-adversarial','robustbench','mico','nist-trojai'];
  const ids=new Set(SOURCE_REGISTRY.map((source)=>source.id));
  return {
    schema:'newcyber.ai-stage1-source-registry-health.v1',
    total:SOURCE_REGISTRY.length,
    counts,
    domestic:domestic.length,
    requestedCorePresent:requestedCore.filter((id)=>ids.has(id)),
    requestedCoreMissing:requestedCore.filter((id)=>!ids.has(id)),
    complete:DIRECTIONS.every((direction)=>counts[direction]>=5)&&domestic.length>=6&&requestedCore.every((id)=>ids.has(id))
  };
}

module.exports={DIRECTIONS,SOURCE_REGISTRY,byDirection,registryHealth};
