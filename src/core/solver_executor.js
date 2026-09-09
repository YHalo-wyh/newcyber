'use strict';

const fsp=require('fs/promises');
const path=require('path');
const { analyzeElfBinary, MAX_ELF_BYTES }=require('./binary_elf_loader');
const { scanX86_64DataRefs }=require('./x86_64_data_refs');
const { scanX86_64ShortDataflow }=require('./x86_64_short_dataflow');
const { analyzeCaptureIntelligence }=require('./capture_intelligence_v3');
const { analyzeFirmwareBuffer }=require('./firmware_workbench');
const { analyzeArtifactTree }=require('./recursive_artifact_analysis');
const { createBinaryArtifact }=require('./artifacts');

const MAX_ATTEMPTS=12;
const MAX_TOTAL_BYTES=192*1024*1024;
const MAX_CAPTURE_BYTES=160*1024*1024;
const MAX_FIRMWARE_BYTES=64*1024*1024;
const MAX_RECURSIVE_BYTES=8*1024*1024;
const RECURSIVE_EXTENSIONS=new Set(['.zip','.tar','.tgz','.gz','.gzip']);

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}
function ext(file){return String(file?.extension||file?.path?.match(/\.[^.\\/]+$/)?.[0]||'').toLowerCase();}
function inside(root,target){const rel=path.relative(root,target);return rel===''||(!rel.startsWith('..'+path.sep)&&rel!=='..'&&!path.isAbsolute(rel));}

async function resolveWorkspaceFile(rootPath,file){
  const root=await fsp.realpath(path.resolve(String(rootPath||'')));
  const lexical=path.resolve(root,String(file?.path||''));
  if(!inside(root,lexical))throw new Error('workspace path escapes root');
  const lst=await fsp.lstat(lexical);
  if(lst.isSymbolicLink())throw new Error('solver executor refuses symlink input');
  if(!lst.isFile())throw new Error('solver executor input is not a regular file');
  const real=await fsp.realpath(lexical);
  if(!inside(root,real))throw new Error('resolved workspace path escapes root');
  return {root,path:real,stat:lst};
}

async function readBounded(rootPath,file,maxBytes,budget){
  const resolved=await resolveWorkspaceFile(rootPath,file);
  const size=Number(resolved.stat.size)||0;
  if(size<=0)throw new Error('input file is empty');
  if(size>maxBytes)throw new Error(`input exceeds adapter limit (${maxBytes} bytes)`);
  if((budget.bytes+size)>MAX_TOTAL_BYTES)throw new Error(`solver executor total read budget exceeded (${MAX_TOTAL_BYTES} bytes)`);
  const buffer=await fsp.readFile(resolved.path);
  budget.bytes+=buffer.length;
  return {buffer,resolved};
}

function mergeRelations(analysis,rows){
  const keys=new Set(list(analysis.relations).map((r)=>`${r.source}|${r.target}|${r.type}|${r.location||''}`));
  let added=0;
  analysis.relations||=[];
  for(const relation of list(rows)){
    const key=`${relation.source}|${relation.target}|${relation.type}|${relation.location||''}`;
    if(keys.has(key))continue;
    analysis.relations.push({...relation,id:`rel_${analysis.relations.length+1}`});keys.add(key);added+=1;
  }
  return added;
}

function mergeOperations(analysis,rows){
  const keys=new Set(list(analysis.operations).map((o)=>`${o.scope||''}|${o.op}|${o.location||''}|${o.pseudo||''}`));
  let added=0;
  analysis.operations||=[];
  for(const operation of list(rows)){
    const key=`${operation.scope||''}|${operation.op}|${operation.location||''}|${operation.pseudo||''}`;
    if(keys.has(key))continue;
    analysis.operations.push(operation);keys.add(key);added+=1;
  }
  return added;
}

function addStandaloneCodeRefs(graph,buffer){
  if(graph?.source?.elf?.bits!==64||graph?.source?.elf?.machine!=='x86-64')return graph;
  const littleEndian=graph.source.elf.endian!=='big';
  const direct=scanX86_64DataRefs(buffer,graph.sections||[],graph.objects||[],[],{littleEndian});
  const flow=scanX86_64ShortDataflow(buffer,graph.sections||[],graph.objects||[],{littleEndian});
  const directRelations=mergeRelations(graph,direct.relations);
  const flowRelations=mergeRelations(graph,flow.relations);
  const directOps=mergeOperations(graph,direct.operations);
  const flowOps=mergeOperations(graph,flow.operations);
  graph.recoverableRelations||=[];
  const recoverKeys=new Set(graph.recoverableRelations.map((item)=>`${item.operation}|${item.location}|${list(item.objects).join('|')}`));
  let recoverable=0;
  for(const item of list(flow.recoverableRelations)){
    const key=`${item.operation}|${item.location}|${list(item.objects).join('|')}`;
    if(recoverKeys.has(key))continue;
    graph.recoverableRelations.push(item);recoverKeys.add(key);recoverable+=1;
  }
  graph.summary={...(graph.summary||{}),operations:list(graph.operations).length,relations:list(graph.relations).length,recoverableRelations:list(graph.recoverableRelations).length,standaloneCodeRefs:directRelations,standaloneCodeOps:directOps,standaloneShortFlowOps:flowOps,standaloneShortFlowRelations:flowRelations,standaloneRecoverable:recoverable,standaloneCodeBytes:Number(direct.scannedBytes)||0,standaloneShortFlowBytes:Number(flow.scannedBytes)||0};
  graph.source={...(graph.source||{}),parser:`${graph.source?.parser||'deterministic-elf'}+executor-x86-v1`};
  return graph;
}

function compactArtifact(artifact){
  if(!artifact)return null;
  return {name:artifact.name,size:artifact.size,sha256:artifact.sha256,mediaType:artifact.mediaType,completeness:artifact.completeness,metadata:artifact.metadata};
}

function compactBinaryGraph(graph){
  return {
    schema:graph.schema,source:graph.source,summary:graph.summary,elf:graph.elf,
    sections:list(graph.sections).slice(0,256),
    objects:list(graph.objects).slice(0,320).map((o)=>({id:o.id,name:o.name,address:o.address,section:o.section,kind:o.kind,size:o.size,structuralName:o.structuralName,fields:o.fields,semanticSuggestions:o.semanticSuggestions,evidence:list(o.evidence).slice(0,12)})),
    relations:list(graph.relations).slice(0,640),operations:list(graph.operations).slice(0,320),recoverableRelations:list(graph.recoverableRelations).slice(0,96),notes:list(graph.notes).slice(0,16)
  };
}

function compactCapture(result){
  return {
    format:result.format,packetCount:result.packetCount,linkTypes:result.linkTypes,truncated:result.truncated,
    highlights:list(result.highlights).slice(0,32),findings:list(result.findings).slice(0,120),nextActions:list(result.nextActions).slice(0,32),
    network:result.network?{protocolCounts:result.network.protocolCounts,topFlows:list(result.network.topFlows).slice(0,80),dnsQueries:list(result.network.dnsQueries).slice(0,200),httpRequests:list(result.network.httpRequests).slice(0,160),rtspEndpoints:list(result.network.rtspEndpoints).slice(0,80),credentials:list(result.network.credentials).slice(0,80),plaintextEvidence:list(result.network.plaintextEvidence).slice(0,160),mavlink:result.network.mavlink||null}:null,
    can:result.can?{parsedFrames:result.can.parsedFrames,uniqueIds:result.can.uniqueIds,eventCandidates:list(result.can.eventCandidates).slice(0,120),isoTpSessions:list(result.can.isoTpSessions).slice(0,100),udsProgramming:result.can.udsProgramming||null}:null,
    datalink:result.datalink?{flows:list(result.datalink.flows).slice(0,120),vendorEvidence:list(result.datalink.vendorEvidence).slice(0,80),pairedFlows:list(result.datalink.pairedFlows).slice(0,80),findings:list(result.datalink.findings).slice(0,80)}:null
  };
}

function compactFirmware(result){
  return {
    magic:list(result.magic).slice(0,80),structures:list(result.structures).slice(0,160),artifactSummaries:list(result.artifacts).slice(0,64).map(compactArtifact).filter(Boolean),
    securityStrings:list(result.securityStrings).slice(0,160),clueSummary:result.clueSummary||{},pipeline:result.pipeline||null,nextActions:list(result.nextActions).slice(0,40),findings:list(result.findings).slice(0,160),
    embeddedCaptures:list(result.embeddedCaptures).slice(0,24).map((item)=>({format:item.format,offset:item.offset,offsetHex:item.offsetHex,endOffset:item.endOffset,endOffsetHex:item.endOffsetHex,packetCount:item.analysis?.packetCount||item.packetCount||0,linkTypes:item.analysis?.linkTypes||item.linkTypes||[],highlights:list(item.analysis?.highlights).slice(0,12)}))
  };
}

function compactRecursive(tree){
  return {
    schema:tree.schema,maxDepth:tree.maxDepth,stats:tree.stats,flags:list(tree.flags),findings:list(tree.findings).slice(0,160),artifacts:list(tree.artifacts).slice(0,48).map(compactArtifact).filter(Boolean),
    nodes:list(tree.nodes).slice(0,32).map((node)=>({depth:node.depth,name:node.name,sha256:node.sha256,size:node.size,magic:node.magic,compression:node.compression,lineage:node.lineage,flags:node.flags,decode:node.decode?{attempted:node.decode.attempted,candidates:list(node.decode.candidates).slice(0,8).map((item)=>({...item,artifact:undefined,artifactSummary:compactArtifact(item.artifact)}))}:null,capture:node.capture?{format:node.capture.format,packetCount:node.capture.packetCount,linkTypes:node.capture.linkTypes,highlights:list(node.capture.highlights).slice(0,12),findings:list(node.capture.findings).slice(0,32)}:null,zip:node.zip?{entries:node.zip.entries,skippedEncrypted:node.zip.skippedEncrypted,skippedUnsupported:node.zip.skippedUnsupported,extracted:list(node.zip.extracted).slice(0,16).map((x)=>({name:x.name,size:x.size,compression:x.compression,artifactSummary:compactArtifact(x.artifact)}))}:null,tar:node.tar?{entries:node.tar.entries,truncated:node.tar.truncated,skippedUnsupported:node.tar.skippedUnsupported,extracted:list(node.tar.extracted).slice(0,16).map((x)=>({name:x.name,size:x.size,artifactSummary:compactArtifact(x.artifact)}))}:null}))
  };
}

function addFileFindings(analysis,file,rows,prefix){
  file.findings||=[];
  const seen=new Set(file.findings.map((x)=>text(x.id)));
  let added=0;
  for(const finding of list(rows)){
    const id=`${prefix}:${file.path}:${text(finding.id)||added+1}`;
    if(seen.has(id))continue;
    file.findings.push({...finding,id,file:file.path,count:1});seen.add(id);added+=1;
  }
  return added;
}

function addFlagCandidates(analysis,file,flags,source){
  analysis.candidates||={flags:[],urls:[],ips:[]};analysis.candidates.flags||=[];file.flags||=[];
  const known=new Set(analysis.candidates.flags.map((item)=>typeof item==='string'?item:text(item?.value||item?.flag)));
  let added=0;
  for(const value of list(flags).map(text).filter(Boolean)){
    if(!file.flags.includes(value))file.flags.push(value);
    if(known.has(value))continue;
    analysis.candidates.flags.push({value,confidence:'candidate',source,file:file.path});known.add(value);added+=1;
  }
  return added;
}

function upsertAutomaticCheck(analysis,id,title,hits){
  analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];
  const existing=analysis.autopilot.automaticChecks.find((item)=>item.id===id);
  if(existing){existing.hits=Math.max(Number(existing.hits)||0,Number(hits)||0);if(!existing.title)existing.title=title;return;}
  analysis.autopilot.automaticChecks.push({id,title,hits:Number(hits)||0});
}

function refreshFindings(analysis){
  const order={high:0,medium:1,low:2,info:3};
  analysis.findings=list(analysis.files).flatMap((file)=>list(file.findings)).sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9)||text(a.file).localeCompare(text(b.file))||(Number(a.line)||0)-(Number(b.line)||0));
  analysis.stats||={};analysis.stats.findings=analysis.findings.length;analysis.stats.flags=list(analysis.files).reduce((sum,file)=>sum+list(file.flags).length,0);
}

function recursiveEligible(file){return RECURSIVE_EXTENSIONS.has(ext(file))||/(?:ZIP|TAR|GZIP)/i.test(text(file?.type));}
function elfEligible(file){const e=ext(file);return ['.elf','.so','.o'].includes(e)||/\bELF\b/i.test(text(file?.type));}

function planSolverExecution(analysis={}){
  const pipeline=analysis.solverPipeline||analysis.challengeSession?.solverPipeline;
  const ready=new Set(list(pipeline?.nodes).filter((item)=>item.state==='ready').map((item)=>item.id));
  const plans=[];
  const files=list(analysis.files);
  const add=(nodeId,adapter,file,maxBytes)=>{if(plans.length>=MAX_ATTEMPTS)return;plans.push({nodeId,adapter,filePath:file.path,file,maxBytes});};
  if(ready.has('reverse'))for(const file of files)if(elfEligible(file))add('reverse','elf-static',file,MAX_ELF_BYTES);
  if(ready.has('traffic'))for(const file of files)if(['.pcap','.pcapng','.cap'].includes(ext(file)))add('traffic','capture-intelligence',file,MAX_CAPTURE_BYTES);
  if(ready.has('firmware'))for(const file of files)if(['.img','.fw','.rom','.trx','.ubi','.squashfs'].includes(ext(file)))add('firmware','firmware-workbench',file,MAX_FIRMWARE_BYTES);
  if(ready.has('recursive'))for(const file of files)if(recursiveEligible(file))add('recursive','recursive-artifact',file,MAX_RECURSIVE_BYTES);
  return plans.slice(0,MAX_ATTEMPTS);
}

async function runPlan(rootPath,analysis,plan,budget){
  const attempt={nodeId:plan.nodeId,adapter:plan.adapter,file:plan.filePath,status:'running',transitions:['ready','running'],detail:'',outputs:{},error:null};
  const {buffer}=await readBounded(rootPath,plan.file,plan.maxBytes,budget);
  if(plan.adapter==='elf-static'){
    if(!(buffer[0]===0x7f&&buffer[1]===0x45&&buffer[2]===0x4c&&buffer[3]===0x46))throw new Error('ELF adapter selected but magic does not match');
    const graph=compactBinaryGraph(addStandaloneCodeRefs(analyzeElfBinary(buffer,path.basename(plan.filePath)),buffer));
    plan.file.metadata={...(plan.file.metadata||{}),binaryDataGraph:graph,solverExecutor:{...(plan.file.metadata?.solverExecutor||{}),reverse:'done'}};
    upsertAutomaticCheck(analysis,'binary-data-graph','ELF / Binary Data Graph',1);
    attempt.outputs={schema:graph.schema,objects:Number(graph.summary?.objects)||0,relations:Number(graph.summary?.relations)||0,operations:Number(graph.summary?.operations)||0,recoverable:Number(graph.summary?.recoverableRelations)||0};
  }else if(plan.adapter==='capture-intelligence'){
    const result=analyzeCaptureIntelligence(buffer);
    if(result.format==='unknown')throw new Error('capture adapter could not validate PCAP/PCAPNG structure');
    const compact=compactCapture(result);
    plan.file.metadata={...(plan.file.metadata||{}),captureIntelligence:compact,solverExecutor:{...(plan.file.metadata?.solverExecutor||{}),traffic:'done'}};
    const findings=addFileFindings(analysis,plan.file,result.findings,'solver-exec-capture');
    upsertAutomaticCheck(analysis,'capture-intelligence','PCAP / 协议递归分析',1);
    attempt.outputs={format:result.format,packets:Number(result.packetCount)||0,findings};
  }else if(plan.adapter==='firmware-workbench'){
    const result=analyzeFirmwareBuffer(buffer,{tryDecompress:false});
    const compact=compactFirmware(result);
    plan.file.metadata={...(plan.file.metadata||{}),firmwareWorkbench:compact,solverExecutor:{...(plan.file.metadata?.solverExecutor||{}),firmware:'done'}};
    const findings=addFileFindings(analysis,plan.file,result.findings,'solver-exec-firmware');
    attempt.outputs={structures:list(result.structures).length,securityStrings:list(result.securityStrings).length,embeddedCaptures:list(result.embeddedCaptures).length,findings};
  }else if(plan.adapter==='recursive-artifact'){
    const seed=createBinaryArtifact({name:path.basename(plan.filePath),buffer,completeness:'complete',provenance:[{source:'solver-executor',workspacePath:plan.filePath}]});
    const tree=analyzeArtifactTree([seed],{maxDepth:2,maxNodes:24,maxNodeBytes:MAX_RECURSIVE_BYTES,maxTotalBytes:32*1024*1024});
    if(!list(tree.nodes).length)throw new Error('recursive adapter produced no analyzable nodes');
    const compact=compactRecursive(tree);
    plan.file.metadata={...(plan.file.metadata||{}),recursiveExecutor:compact,solverExecutor:{...(plan.file.metadata?.solverExecutor||{}),recursive:'done'}};
    const findings=addFileFindings(analysis,plan.file,tree.findings,'solver-exec-recursive');
    const flags=addFlagCandidates(analysis,plan.file,tree.flags,'solver-executor:recursive');
    upsertAutomaticCheck(analysis,'recursive-artifact','恢复产物递归回灌',1);
    attempt.outputs={nodes:Number(tree.stats?.analyzedNodes)||0,artifacts:Number(tree.stats?.artifacts)||0,flags,findings};
  }else throw new Error(`unsupported solver executor adapter: ${plan.adapter}`);
  attempt.status='done';attempt.transitions.push('done');attempt.detail='deterministic adapter completed';
  return attempt;
}

async function executeReadySolvers(rootPath,analysis={},options={}){
  if(options.solverExecutor===false)return {schema:'newcyber.solver-execution.v1',version:1,enabled:false,attempts:[],summary:{planned:0,done:0,blocked:0,bytesRead:0}};
  const plans=planSolverExecution(analysis);
  const budget={bytes:0};const attempts=[];
  for(const plan of plans){
    if(attempts.length>=MAX_ATTEMPTS)break;
    try{attempts.push(await runPlan(rootPath,analysis,plan,budget));}
    catch(error){attempts.push({nodeId:plan.nodeId,adapter:plan.adapter,file:plan.filePath,status:'blocked',transitions:['ready','running','blocked'],detail:'automatic adapter stopped',outputs:{},error:text(error?.message||error)});}
  }
  refreshFindings(analysis);
  return {schema:'newcyber.solver-execution.v1',version:1,enabled:true,attempts,summary:{planned:plans.length,done:attempts.filter((x)=>x.status==='done').length,blocked:attempts.filter((x)=>x.status==='blocked').length,bytesRead:budget.bytes},limits:{maxAttempts:MAX_ATTEMPTS,maxTotalBytes:MAX_TOTAL_BYTES},notes:['Executor 只消费当前 Pipeline 的 READY 节点；SKIPPED/BLOCKED 节点不会被强行执行。','所有首批 Adapter 都是离线、只读、确定性解析；不会运行题目程序、脚本或自动访问远程服务。']};
}

module.exports={MAX_ATTEMPTS,MAX_TOTAL_BYTES,MAX_CAPTURE_BYTES,MAX_FIRMWARE_BYTES,MAX_RECURSIVE_BYTES,resolveWorkspaceFile,planSolverExecution,executeReadySolvers,addStandaloneCodeRefs,compactBinaryGraph};
