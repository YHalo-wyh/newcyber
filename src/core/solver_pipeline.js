'use strict';

const STATE_RANK=Object.freeze({done:5,partial:4,blocked:3,ready:2,skipped:1});

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}
function ext(file){return String(file?.extension||file?.path?.match(/\.[^.\\/]+$/)?.[0]||'').toLowerCase();}
function flagValue(item){return typeof item==='string'?item:text(item?.value||item?.flag);}
function isVerified(item){return Boolean(item&&typeof item==='object'&&(item.verified===true||text(item.confidence).toLowerCase()==='verified'));}
function autoChecks(analysis){return new Map(list(analysis.autopilot?.automaticChecks).map((item)=>[text(item.id),item]));}
function check(checks,id){const item=checks.get(id);return item?{hits:Number(item.hits)||0,title:text(item.title)}:null;}
function anyFile(analysis,predicate){return list(analysis.files).some(predicate);}
function metadataAny(analysis,keys){return anyFile(analysis,(file)=>keys.some((key)=>file.metadata?.[key]));}
function fileExtensions(analysis){return new Set(list(analysis.files).map(ext));}

function node(id,title,phase,state,detail='',extra={}){
  return {id,title,phase,state,detail:text(detail),evidence:[],inputs:[],outputs:[],dependsOn:[],...extra};
}

function evidenceCount(value){
  if(Array.isArray(value))return value.length;
  if(value&&typeof value==='object')return Object.keys(value).length;
  return value?1:0;
}

function buildSolverPipeline(analysis={}){
  const files=list(analysis.files);
  const checks=autoChecks(analysis);
  const exts=fileExtensions(analysis);
  const nodes=[];
  const push=(entry)=>{nodes.push(entry);return entry;};

  push(node('ingest','附件摄取 / 文件指纹','ingest',files.length?'done':'blocked',files.length?`${files.length} 个附件进入只读分析`:'等待题目附件',{
    outputs:files.slice(0,16).map((file)=>text(file.path)).filter(Boolean),evidence:[`${files.length} files`]
  }));

  const triageHits=Number(analysis.autopilot?.summary?.automaticCheckHits)||0;
  const track=analysis.autopilot?.track;
  push(node('triage','题型识别 / 自动路由','triage',files.length?'done':'blocked',track?.title?`${track.title} · score ${track.score||0}`:'未锁定单一赛道，继续按附件能力路由',{
    dependsOn:['ingest'],evidence:[`${checks.size} analyzer families`,`${triageHits} evidence hits`]
  }));

  const decode=check(checks,'auto-decode');
  const encodedSignal=anyFile(analysis,(file)=>list(file.metadata?.autoDecode?.attempts).length||list(file.metadata?.autoDecode?.candidates).length);
  push(node('decode','编码 / 压缩 / XOR 递归试解','solve',decode||encodedSignal?'done':'skipped',decode?`${decode.hits} 个附件命中自动试解`:'未发现需要递归解码的强证据',{
    dependsOn:['triage'],evidence:decode?[`${decode.hits} hit(s)`]:[]
  }));

  const recursive=check(checks,'recursive-artifact');
  const recovered=list(analysis.autopilot?.artifacts);
  push(node('recursive','恢复产物递归回灌','solve',recursive||recovered.length?'done':'skipped',recovered.length?`恢复 ${recovered.length} 个可跟踪产物并继续扫描`:'当前没有完整恢复产物',{
    dependsOn:['decode'],outputs:recovered.slice(0,12).map((item)=>text(item.name||item.kind)).filter(Boolean),evidence:recursive?[`${recursive.hits} recursive source(s)`]:[]
  }));

  const binaryPresent=[...exts].some((x)=>['.elf','.so','.exe','.dll','.o','.bin'].includes(x))||anyFile(analysis,(file)=>/ELF|PE32/i.test(text(file.type)));
  const binaryGraph=metadataAny(analysis,['binaryDataGraph','elf'])||check(checks,'binary-data-graph');
  push(node('reverse','ELF / Binary Data Graph','solve',binaryGraph?'done':binaryPresent?'ready':'skipped',binaryGraph?'已恢复二进制物理层 / 数据关系证据':binaryPresent?'存在二进制附件，可继续进入静态关系恢复':'无二进制对象',{
    dependsOn:['triage'],inputs:binaryPresent?['binary/object file']:[],evidence:binaryGraph?['binary relationship evidence']:[]
  }));

  const capture=check(checks,'capture-intelligence');
  const capturePresent=[...exts].some((x)=>['.pcap','.pcapng','.cap'].includes(x));
  push(node('traffic','PCAP / 协议递归分析','solve',capture?'done':capturePresent?'ready':'skipped',capture?`${capture.hits} 个抓包进入深度协议解析`:capturePresent?'存在抓包，等待/准备协议解析':'无抓包输入',{
    dependsOn:['triage'],evidence:capture?[`${capture.hits} capture(s)`]:[]
  }));

  const firmware=metadataAny(analysis,['firmware','firmwareWorkbench','firmwareUpdateAudit'])||check(checks,'firmware-update');
  const firmwarePresent=[...exts].some((x)=>['.img','.fw','.rom','.trx','.ubi','.squashfs'].includes(x));
  push(node('firmware','固件结构 / 嵌套对象恢复','solve',firmware?'done':firmwarePresent?'ready':'skipped',firmware?'固件结构和信任链证据已进入自动链':firmwarePresent?'存在固件附件，可继续结构恢复':'无固件对象',{
    dependsOn:['triage'],evidence:firmware?['firmware evidence']:[]
  }));

  const aiCheck=check(checks,'ai-model');
  const aiPresent=[...exts].some((x)=>['.onnx','.safetensors','.pt','.pth','.pkl','.pickle','.joblib','.npy','.gguf'].includes(x));
  push(node('ai-model','AI 模型 / 数据静态分析','solve',aiCheck?'done':aiPresent?'ready':'skipped',aiCheck?`${aiCheck.hits} 个 AI 工件已自动审计`:aiPresent?'存在 AI 模型/数据附件，可继续专项分析':'无 AI 模型工件',{
    dependsOn:['triage'],evidence:aiCheck?[`${aiCheck.hits} AI artifact(s)`]:[]
  }));

  const arithmetic=analysis.modelArithmeticAuto;
  if(list(arithmetic?.attempts).length){
    const result=arithmetic.best?.result||{};
    const state=result.status==='flag-recovered'?'done':result.status==='secret-recovered'?'partial':result.status==='gap'?'blocked':'partial';
    push(node('model-arithmetic','模型算术 / Hidden Head','derive',state,result.flag?`恢复 ${result.flag}`:result.solver?.status==='unique'?'唯一 hidden secret 已恢复，Flag 派生未闭环':result.gap?.detail||`尝试 ${arithmetic.attempts.length} 组 bundle`,{
      dependsOn:['ai-model'],evidence:[`${arithmetic.attempts.length} attempt(s)`],outputs:result.flag?[result.flag]:[]
    }));
  }else if(aiPresent){
    push(node('model-arithmetic','模型算术 / Hidden Head','derive','skipped','没有足够证据证明应套用模型算术关系',{dependsOn:['ai-model']}));
  }

  const sca=analysis.scaAutopilot;
  if(sca&&sca.status!=='not-applicable'&&sca.status!=='disabled'){
    const result=sca.result||{};
    const state=result.status==='flag-recovered'?'done':result.gap?'blocked':result.status==='secret-recovered'?'partial':'partial';
    push(node('sca','功耗侧信道 → Transformer Oracle','derive',state,result.flag?`Oracle 已验证 ${result.flag}`:result.gap?`${result.gap.code} · ${result.gap.detail||''}`:sca.error||result.status||'专项链已执行',{
      dependsOn:['ai-model'],evidence:result.gap?[result.gap.code]:[],outputs:result.flag?[result.flag]:[]
    }));
  }

  const vehicle=check(checks,'vehicle');
  if(vehicle)push(node('vehicle','CAN / ISO-TP / UDS','solve','done',`${vehicle.hits} 个车辆协议输入已解析`,{dependsOn:['triage'],evidence:[`${vehicle.hits} hit(s)`]}));
  const lowaltHits=['capture-intelligence','gnss-audit','uav-regulatory','firmware-update'].map((id)=>check(checks,id)).filter(Boolean).reduce((sum,x)=>sum+x.hits,0);
  if(lowaltHits)push(node('lowalt','MAVLink / UAV / GNSS','solve','done',`${lowaltHits} 项低空协议/场景证据进入分析链`,{dependsOn:['triage'],evidence:[`${lowaltHits} hit(s)`]}));
  const web3=check(checks,'web3');
  if(web3)push(node('web3','EVM / Solidity 数据流','solve','done',`${web3.hits} 个 Web3 工件已分析`,{dependsOn:['triage'],evidence:[`${web3.hits} hit(s)`]}));

  const vuln=check(checks,'vulnerability-candidates');
  const advisory=analysis.advisories?.summary;
  if(vuln||advisory)push(node('supply-chain','组件版本 / Advisory / 可达性','correlate','done',vuln?`${vuln.hits} 个统一漏洞候选`:`affected ${Number(advisory?.affected)||0} · unknown ${Number(advisory?.unknown)||0}`,{
    dependsOn:['triage'],evidence:vuln?[`${vuln.hits} candidate(s)`]:[]
  }));

  const rawFlags=[...list(analysis.candidates?.flags),...list(analysis.autopilot?.flags)];
  const verified=rawFlags.filter(isVerified).map(flagValue).filter(Boolean);
  const candidates=rawFlags.filter((item)=>!isVerified(item)).map(flagValue).filter(Boolean);
  let verifyState='blocked';let verifyDetail='没有形成可验证 Flag';
  if(verified.length){verifyState='done';verifyDetail=`verified · ${verified[0]}`;}
  else if(candidates.length){verifyState='partial';verifyDetail=`${candidates.length} 个候选仍需 verifier`;}
  else if(files.length){verifyState='ready';verifyDetail='等待上游 solver 产生可验证候选';}
  const solverDeps=nodes.filter((item)=>['solve','derive','correlate'].includes(item.phase)&&item.state!=='skipped').map((item)=>item.id);
  push(node('verify','结果验证 / Flag Gate','verify',verifyState,verifyDetail,{dependsOn:solverDeps,inputs:candidates.slice(0,4),outputs:verified.slice(0,4),evidence:[verified.length?`${verified.length} verified`:candidates.length?`${candidates.length} candidate(s)`:'0 candidate']}));

  const primaryGap=list(analysis.autoSolve?.gaps)[0]||analysis.scaAutopilot?.result?.gap||null;
  if(!verified.length){
    push(node('handoff','最小缺口 / Local AI Handoff','handoff',primaryGap?'blocked':'ready',primaryGap?`${primaryGap.code||'GAP'} · ${primaryGap.detail||''}`:'确定性链无闭环结果，准备上下文接管',{
      dependsOn:['verify'],evidence:primaryGap?[text(primaryGap.code)]:[]
    }));
  }

  const active=nodes.find((item)=>item.state==='blocked'&&item.phase!=='verify')||nodes.find((item)=>item.state==='ready'&&item.phase!=='verify')||nodes.find((item)=>item.id==='verify');
  const done=nodes.filter((item)=>item.state==='done').length;
  const partial=nodes.filter((item)=>item.state==='partial').length;
  const blocked=nodes.filter((item)=>item.state==='blocked').length;
  const ready=nodes.filter((item)=>item.state==='ready').length;
  const skipped=nodes.filter((item)=>item.state==='skipped').length;

  return {
    schema:'newcyber.solver-pipeline.v1',version:1,
    nodes:nodes.sort((a,b)=>{
      const phase={ingest:0,triage:1,solve:2,derive:3,correlate:4,verify:5,handoff:6};
      return (phase[a.phase]??9)-(phase[b.phase]??9)||(STATE_RANK[b.state]||0)-(STATE_RANK[a.state]||0);
    }),
    activeNodeId:active?.id||null,
    summary:{total:nodes.length,done,partial,blocked,ready,skipped},
    notes:['Pipeline 只展示实际分析证据与明确适用条件；没有证据的模板保持 skipped，不会为了“看起来跑得多”而伪造执行记录。','READY 表示当前附件已经具备继续进入该确定性能力的条件；BLOCKED 表示已有求解链明确停在最小缺口。']
  };
}

module.exports={buildSolverPipeline};
