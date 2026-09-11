'use strict';

const path=require('node:path');

const MAX_ROWS=100000;
const MAX_JSON_NODES=6000;

function list(value){return Array.isArray(value)?value:[];}
function scalar(value){return typeof value==='string'||typeof value==='number';}
function norm(value){return String(value??'').replace(/\\/g,'/').replace(/^\.\//,'').trim();}
function basename(value){return path.posix.basename(norm(value));}
function numericMaybe(value){if(typeof value==='number'&&Number.isFinite(value))return value;const text=String(value??'').trim();return /^-?\d+$/.test(text)?Number(text):value;}
function splitDelimited(line,delimiter){const out=[];let value='',quote=false;for(let i=0;i<line.length;i+=1){const ch=line[i];if(ch==='"'){if(quote&&line[i+1]==='"'){value+='"';i+=1;}else quote=!quote;continue;}if(ch===delimiter&&!quote){out.push(value);value='';}else value+=ch;}out.push(value);return out;}

function addMapping(rows,entry){
  const file=norm(entry.file);if(!file||entry.label===undefined||entry.label===null||entry.label==='')return;const normalized={file,label:numericMaybe(entry.label),id:entry.id??null,source:entry.source||null,sourceFile:entry.sourceFile||null};
  if(!rows.some((item)=>item.file===normalized.file&&String(item.label)===String(normalized.label)&&String(item.id??'')===String(normalized.id??'')))rows.push(normalized);
}
function rowFields(row){if(!row||typeof row!=='object'||Array.isArray(row))return null;const file=row.file??row.filename??row.path??row.sample??row.image??row.name;const label=row.assignedLabel??row.folderLabel??row.bucketLabel??row.classLabel??row.targetLabel??row.label??row.class??row.category;const id=row.id??row.index??row.sampleId??row.sample_id??null;return file!==undefined&&label!==undefined?{file,label,id}:null;}
function walk(value,visit,depth=0,state={count:0}){if(value===null||value===undefined||depth>6||state.count>=MAX_JSON_NODES)return;state.count+=1;visit(value);if(Array.isArray(value)){for(const child of value.slice(0,MAX_JSON_NODES-state.count))walk(child,visit,depth+1,state);}else if(typeof value==='object')for(const child of Object.values(value))walk(child,visit,depth+1,state);}

function discoverJsonCandidateMappings(file,body){
  let parsed;try{parsed=JSON.parse(body);}catch{return[];}const rows=[];
  walk(parsed,(value)=>{
    if(Array.isArray(value)){for(const row of value.slice(0,MAX_ROWS)){const fields=rowFields(row);if(fields)addMapping(rows,{...fields,source:'json-row',sourceFile:file});}return;}
    if(!value||typeof value!=='object')return;const fields=rowFields(value);if(fields)addMapping(rows,{...fields,source:'json-object',sourceFile:file});
    const entries=Object.entries(value);if(entries.length&&entries.length<=MAX_ROWS&&entries.every(([key,val])=>/\.(?:png|jpe?g|bmp|webp|npy)$/i.test(key)&&scalar(val)))for(const [key,val] of entries)addMapping(rows,{file:key,label:val,source:'json-file-label-map',sourceFile:file});
  });
  return rows.slice(0,MAX_ROWS);
}
function discoverDelimitedCandidateMappings(file,body){
  const lines=String(body||'').split(/\r?\n/).filter((line)=>line.trim()).slice(0,MAX_ROWS+1);if(lines.length<2)return[];const delimiter=lines[0].includes('\t')?'\t':',';const headers=splitDelimited(lines[0],delimiter).map((x)=>x.trim());
  const fileIndex=headers.findIndex((x)=>/^(?:file|filename|path|sample|image|name)$/i.test(x));const labelIndex=headers.findIndex((x)=>/^(?:assigned[_-]?label|folder[_-]?label|bucket[_-]?label|class[_-]?label|target[_-]?label|label|class|category)$/i.test(x));const idIndex=headers.findIndex((x)=>/^(?:id|index|sample[_-]?id)$/i.test(x));if(fileIndex<0||labelIndex<0)return[];const rows=[];
  for(let i=1;i<lines.length;i+=1){const cells=splitDelimited(lines[i],delimiter);if(cells.length<=Math.max(fileIndex,labelIndex))continue;addMapping(rows,{file:cells[fileIndex],label:cells[labelIndex],id:idIndex>=0?numericMaybe(cells[idIndex]):null,source:'delimited-manifest',sourceFile:file});}
  return rows;
}

function addClass(map,name,index,source,sourceFile){if(name===undefined||index===undefined)return;const idx=Number(index);if(!Number.isInteger(idx)||idx<0)return;const key=String(name).trim();if(!key)return;if(!map.has(key))map.set(key,{name:key,index:idx,source,sourceFile});}
function discoverJsonClassMappings(file,body){
  let parsed;try{parsed=JSON.parse(body);}catch{return[];}const map=new Map();
  walk(parsed,(value)=>{
    if(!value||typeof value!=='object'||Array.isArray(value))return;
    for(const key of ['class_to_idx','classToIdx','label_to_idx','labelToIdx']){const dict=value[key];if(dict&&typeof dict==='object'&&!Array.isArray(dict))for(const [name,index] of Object.entries(dict))addClass(map,name,index,key,file);}
    for(const key of ['classes','labels','class_names','classNames','output_labels','outputLabels']){const arr=value[key];if(Array.isArray(arr)&&arr.length>=2&&arr.length<=100000&&arr.every((x)=>typeof x==='string'))arr.forEach((name,index)=>addClass(map,name,index,key,file));}
    for(const key of ['idx_to_class','idxToClass','id_to_label','idToLabel']){const dict=value[key];if(dict&&typeof dict==='object'&&!Array.isArray(dict))for(const [index,name] of Object.entries(dict))if(typeof name==='string')addClass(map,name,index,key,file);}
  });
  return[...map.values()];
}
function discoverPythonClassMappings(file,body){
  const map=new Map();let match;const dictRe=/(?:class_to_idx|classToIdx|label_to_idx|labelToIdx)\s*=\s*\{([^}]{1,20000})\}/gi;
  while((match=dictRe.exec(body))){const entryRe=/["']([^"']+)["']\s*:\s*(-?\d+)/g;let entry;while((entry=entryRe.exec(match[1])))addClass(map,entry[1],entry[2],'python-class-to-idx',file);}
  const listRe=/(?:classes|labels|class_names|output_labels)\s*=\s*\[([^\]]{1,20000})\]/gi;while((match=listRe.exec(body))){const names=[];const stringRe=/["']([^"']+)["']/g;let item;while((item=stringRe.exec(match[1])))names.push(item[1]);if(names.length>=2)names.forEach((name,index)=>addClass(map,name,index,'python-class-list',file));}
  return[...map.values()];
}

function buildCandidateIndex(sources=[]){
  const mappings=[],classes=[];
  for(const source of list(sources)){const file=String(source.file||source.path||'source'),body=String(source.text||source.content||'');if(!body)continue;const ext=path.extname(file).toLowerCase();mappings.push(...discoverJsonCandidateMappings(file,body));classes.push(...discoverJsonClassMappings(file,body),...discoverPythonClassMappings(file,body));if(ext==='.csv'||ext==='.tsv')mappings.push(...discoverDelimitedCandidateMappings(file,body));}
  const exact=new Map(),base=new Map(),ambiguousBases=new Set();for(const row of mappings){const key=norm(row.file);if(!exact.has(key))exact.set(key,row);const b=basename(key);if(base.has(b)&&String(base.get(b).label)!==String(row.label))ambiguousBases.add(b);else if(!base.has(b))base.set(b,row);}for(const key of ambiguousBases)base.delete(key);
  const classMap=new Map(),indexMap=new Map();for(const row of classes){if(!classMap.has(row.name))classMap.set(row.name,row);if(!indexMap.has(row.index))indexMap.set(row.index,row);}
  return{schema:'newcyber.challenge-candidate-index.v2',mappings:mappings.slice(0,MAX_ROWS),classes:[...classMap.values()],stats:{candidateMappings:mappings.length,classMappings:classMap.size,ambiguousBasenames:ambiguousBases.size},_exact:exact,_base:base,_classMap:classMap,_indexMap:indexMap};
}
function targetSet(hints){return new Set(list(hints).map((row)=>String(Array.isArray(row)?row[1]:(row?.adversarialLabel??row?.targetLabel??row?.target??row?.to))));}
function normalizeLabelForTargets(label,index,targets){
  const direct=numericMaybe(label);if(targets.has(String(direct)))return direct;const cls=index._classMap.get(String(direct));if(cls&&targets.has(String(cls.index)))return cls.index;const numeric=Number(direct);if(Number.isInteger(numeric)){const byIndex=index._indexMap.get(numeric);if(byIndex&&targets.has(String(byIndex.name)))return byIndex.name;}return direct;
}
function candidateIdentity(candidatePath,index,hints){
  const relative=norm(candidatePath);const mapped=index._exact.get(relative)||index._base.get(basename(relative))||null;const targets=targetSet(hints);
  if(mapped){const label=normalizeLabelForTargets(mapped.label,index,targets);if(targets.has(String(label)))return{label,id:mapped.id??null,source:mapped.source,sourceFile:mapped.sourceFile,mappedFile:mapped.file};}
  const parts=relative.split('/').slice(0,-1).reverse();for(const part of parts){if(targets.has(String(part)))return{label:numericMaybe(part),id:null,source:'parent-folder',sourceFile:null,mappedFile:null};const cls=index._classMap.get(part);if(cls&&targets.has(String(cls.index)))return{label:cls.index,id:null,source:'class-map+parent-folder',sourceFile:cls.sourceFile,mappedFile:null};const numeric=Number(part);if(Number.isInteger(numeric)){const byIndex=index._indexMap.get(numeric);if(byIndex&&targets.has(byIndex.name))return{label:byIndex.name,id:null,source:'index-map+parent-folder',sourceFile:byIndex.sourceFile,mappedFile:null};}}
  return null;
}
function outputLabelsForHints(index,hints){
  if(!index?._indexMap?.size)return null;const targets=new Set();for(const row of list(hints)){const a=Array.isArray(row)?row[0]:(row?.originLabel??row?.origin??row?.from);const b=Array.isArray(row)?row[1]:(row?.adversarialLabel??row?.targetLabel??row?.target??row?.to);targets.add(String(a));targets.add(String(b));}
  const max=Math.max(...index._indexMap.keys());if(!Number.isInteger(max)||max<1||max>100000)return null;const labels=[];for(let i=0;i<=max;i+=1){const cls=index._indexMap.get(i);if(!cls)return null;labels.push(targets.has(cls.name)?cls.name:i);}
  return labels;
}

module.exports={splitDelimited,discoverJsonCandidateMappings,discoverDelimitedCandidateMappings,discoverJsonClassMappings,discoverPythonClassMappings,buildCandidateIndex,normalizeLabelForTargets,candidateIdentity,outputLabelsForHints};
