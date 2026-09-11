'use strict';

function list(value){return Array.isArray(value)?value:[];}
function hintPair(row){if(Array.isArray(row)&&row.length>=2)return[row[0],row[1]];if(row&&typeof row==='object'){const a=row.originLabel??row.origin??row.from,b=row.adversarialLabel??row.targetLabel??row.target??row.to;if(a!==undefined&&b!==undefined)return[a,b];}return null;}
function numericLabel(value){if(typeof value==='number'&&Number.isInteger(value))return value;const text=String(value??'').trim();return /^-?\d+$/.test(text)?Number(text):null;}
function mapsFromIndex(index){const byName=new Map(),byIndex=new Map();for(const row of list(index?.classes)){if(row?.name===undefined||!Number.isInteger(Number(row?.index)))continue;const idx=Number(row.index);if(!byName.has(String(row.name)))byName.set(String(row.name),idx);if(!byIndex.has(idx))byIndex.set(idx,String(row.name));}return{byName,byIndex};}
function mapLabel(value,maps){const numeric=numericLabel(value);if(numeric!==null)return{ok:true,value:numeric,source:'numeric'};const name=String(value??'');if(maps.byName.has(name))return{ok:true,value:maps.byName.get(name),source:'class-map'};return{ok:false,value,source:'unresolved'};}

function normalizeScoreSpace(hints,runs,candidateIndex=null){
  const maps=mapsFromIndex(candidateIndex);const pairs=[];const unresolved=[];let mappedNames=0;
  for(let i=0;i<list(hints).length;i+=1){const pair=hintPair(hints[i]);if(!pair){unresolved.push({kind:'hint',index:i,value:hints[i]});continue;}const a=mapLabel(pair[0],maps),b=mapLabel(pair[1],maps);if(!a.ok)unresolved.push({kind:'hint-origin',index:i,value:pair[0]});if(!b.ok)unresolved.push({kind:'hint-target',index:i,value:pair[1]});if(a.source==='class-map'||b.source==='class-map')mappedNames+=1;pairs.push([a.value,b.value]);}
  const normalizedRuns=list(runs).map((run,index)=>{const mapped=mapLabel(run?.assignedLabel,maps);if(!mapped.ok)unresolved.push({kind:'assigned-label',index,value:run?.assignedLabel,id:run?.id});if(mapped.source==='class-map')mappedNames+=1;return{...run,assignedLabel:mapped.value};});
  if(unresolved.length)return{schema:'newcyber.challenge-score-space.v1',status:'gap',hints:pairs,runs:normalizedRuns,unresolved:unresolved.slice(0,64),mapping:{classes:maps.byName.size,mappedNames}};
  return{schema:'newcyber.challenge-score-space.v1',status:'ready',hints:pairs,runs:normalizedRuns,unresolved:[],mapping:{classes:maps.byName.size,mappedNames,mode:mappedNames?'class-map-to-output-index':'numeric-index'}};
}

module.exports={hintPair,numericLabel,mapsFromIndex,mapLabel,normalizeScoreSpace};
