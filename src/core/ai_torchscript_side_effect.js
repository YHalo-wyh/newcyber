'use strict';

const crypto=require('crypto');

const MAX_SOURCE_CHARS=2*1024*1024;

function stripPythonComments(text){
  return String(text||'').split(/\r?\n/).map((line)=>{
    let quote=null,escaped=false;
    for(let i=0;i<line.length;i++){
      const ch=line[i];
      if(escaped){escaped=false;continue;}
      if(ch==='\\'&&quote){escaped=true;continue;}
      if(quote){if(ch===quote)quote=null;continue;}
      if(ch==='"'||ch==="'"){quote=ch;continue;}
      if(ch==='#')return line.slice(0,i);
    }
    return line;
  }).join('\n');
}
function lineAt(text,index){return text.slice(0,Math.max(0,index)).split(/\r?\n/).length;}
function idFor(value){return `torch-chain-${crypto.createHash('sha256').update(String(value)).digest('hex').slice(0,20)}`;}
function parsePath(args){const m=String(args||'').match(/^\s*[rubfRUBF]*(["'])(.*?)\1/);return m?m[2]:null;}
function parseShared(args){const m=String(args||'').match(/\bshared\s*=\s*(True|False)\b/i);return m?m[1].toLowerCase()==='true':null;}
function fromFileBindings(text){
  const out=[];const re=/\b([A-Za-z_]\w*)\s*=\s*torch\.from_file\s*\(([^\n)]*)\)/g;
  for(const m of text.matchAll(re))out.push({variable:m[1],args:m[2],path:parsePath(m[2]),shared:parseShared(m[2]),line:lineAt(text,m.index),evidence:m[0].trim()});
  return out;
}
function copyBindings(text){
  const out=[];const re=/\b([A-Za-z_]\w*)\s*(?:\[[^\n\]]*\])?\.copy_\s*\(\s*([A-Za-z_]\w*)\s*(?:\[[^\n\]]*\])?\s*\)/g;
  for(const m of text.matchAll(re))out.push({destination:m[1],source:m[2],line:lineAt(text,m.index),evidence:m[0].trim()});
  return out;
}
function jitSurfaces(text){
  const patterns=[
    ['jit-script',/\btorch\.jit\.script\s*\(/g],['jit-trace',/\btorch\.jit\.trace\s*\(/g],['jit-load',/\btorch\.jit\.load\s*\(/g],['jit-save',/\b(?:torch\.jit\.save\s*\(|[A-Za-z_]\w*\.save\s*\([^\n)]*\.pt["'][^\n)]*\))/g]
  ];
  const out=[];for(const [kind,re] of patterns)for(const m of text.matchAll(re))out.push({kind,line:lineAt(text,m.index),evidence:m[0].trim()});
  return out;
}

function auditTorchScriptSideEffects(input=''){
  const source=stripPythonComments(String(input||'').slice(0,MAX_SOURCE_CHARS));
  const mapped=fromFileBindings(source),copies=copyBindings(source),jit=jitSurfaces(source);
  const reads=mapped.filter((item)=>item.shared!==true);
  const writes=mapped.filter((item)=>item.shared===true);
  const copyFlows=[];
  for(const copy of copies){
    const read=reads.find((item)=>item.variable===copy.source);
    const write=writes.find((item)=>item.variable===copy.destination);
    if(read&&write)copyFlows.push({source:read,destination:write,copy});
  }
  const weightsOnlyTrue=/\bweights_only\s*=\s*True\b/.test(source)||/weights_only\s*[:=]\s*["']?true/i.test(source);
  const unrestrictedLoad=/\btorch\.load\s*\([^\n)]*weights_only\s*=\s*False\b/.test(source);
  const uploadSurface=/(?:\/upload\b|files?\s*\[["']model["']\]|UploadFile|request\.files|model[_-]?upload)/i.test(source);
  const resultSurface=/(?:\/result\b|results?\/|result_path|download)/i.test(source);
  const jitExecutable=jit.some((item)=>['jit-script','jit-trace','jit-load'].includes(item.kind));
  const complete=Boolean(jitExecutable&&copyFlows.length);
  const findings=[];
  if(jitExecutable)findings.push({id:'torchscript-executable-model-surface',severity:'medium',title:'存在 TorchScript/JIT 可执行模型面',evidence:jit.slice(0,4),meaning:'TorchScript/JIT 模型具有独立执行语义，不能仅用 pickle/weights_only 防护结论覆盖。'});
  for(const item of reads)findings.push({id:'torch-from-file-read-surface',severity:'medium',title:'模型代码映射读取文件',line:item.line,evidence:item.evidence,meaning:'torch.from_file(shared!=True) 可将本地文件内容映射为 Tensor；在不可信模型执行上下文中需要单独审计。'});
  for(const item of writes)findings.push({id:'torch-from-file-shared-write-surface',severity:'high',title:'模型代码映射可写文件',line:item.line,evidence:item.evidence,meaning:'torch.from_file(shared=True) 创建共享可写映射，Tensor mutation 可能同步修改底层文件。'});
  if(complete)findings.push({id:'torchscript-file-side-effect-chain',severity:'high',title:'TorchScript 文件读写副作用链成立',evidence:copyFlows.slice(0,4).map((flow)=>`${flow.source.variable}:${flow.source.path||'?'} -> ${flow.destination.variable}:${flow.destination.path||'?'} @L${flow.copy.line}`),meaning:'静态证据同时覆盖 JIT/TorchScript、文件读取映射、shared 写映射和 copy_ 数据流；这是具体的模型执行副作用 Candidate。'});
  if(weightsOnlyTrue&&jitExecutable)findings.push({id:'weights-only-does-not-cover-jit',severity:'high',title:'weights_only=True 不能证明 TorchScript 执行安全',evidence:'weights_only=True + torch.jit.*',meaning:'weights_only 约束的是对应反序列化路径；当前源码另有 JIT/TorchScript 执行与文件副作用面，不能把该开关当成统一安全边界。'});
  const strongest=copyFlows[0]||null;
  const candidateObject=complete?{
    kind:'torchscript-file-side-effect-chain',
    candidateId:idFor(JSON.stringify({jit:jit.map((x)=>x.kind),read:strongest.source.path,write:strongest.destination.path,copy:strongest.copy.evidence})),
    executionSurface:jit.find((item)=>['jit-script','jit-trace','jit-load'].includes(item.kind))?.kind||null,
    read:{variable:strongest.source.variable,path:strongest.source.path,shared:strongest.source.shared,line:strongest.source.line},
    write:{variable:strongest.destination.variable,path:strongest.destination.path,shared:true,line:strongest.destination.line},
    mutation:{kind:'copy_',line:strongest.copy.line},
    uploadSurface,resultSurface,
    mitigationContext:{weightsOnlyTrue,unrestrictedLoad}
  }:null;
  return {
    schema:'newcyber.ai-torchscript-side-effect.v1',recognized:Boolean(jitExecutable||mapped.length),candidate:complete,verified:false,
    verdict:complete?'side-effect-chain-candidate':jitExecutable?'jit-surface-needs-dataflow':'no-explicit-torchscript-side-effect-chain',
    surfaces:{jitExecutable,uploadSurface,resultSurface,weightsOnlyTrue,unrestrictedLoad},mappedFiles:mapped,copyFlows,findings,candidateObject,
    notes:['静态 Candidate 不等于目标环境已利用成功；本模块不会生成、加载或执行不可信模型。','weights_only=True 只能作为相应 torch.load 反序列化路径的缓解证据，不能自动清除独立 TorchScript/JIT 执行风险。']
  };
}

module.exports={MAX_SOURCE_CHARS,stripPythonComments,fromFileBindings,copyBindings,jitSurfaces,auditTorchScriptSideEffects};
