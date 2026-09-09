'use strict';

const PATH_LIMIT=40;
const FINDING_LIMIT=24;
const EVIDENCE_LIMIT=360;

const TEMPLATE_CATALOG=Object.freeze([
  {id:'workspace-triage',title:'附件识别 / 题型路由',family:'generic'},
  {id:'auto-decode',title:'编码 / 压缩 / XOR 递归试解',family:'generic'},
  {id:'context-crypto',title:'上下文密码链恢复',family:'crypto'},
  {id:'model-arithmetic-auto',title:'模型算术 / Hidden Head',family:'ai'},
  {id:'sca-autopilot',title:'功耗侧信道 → Transformer',family:'ai'},
  {id:'binary-data-graph',title:'ELF / Binary Data Graph',family:'reverse'},
  {id:'capture-intelligence',title:'PCAP / 协议递归分析',family:'traffic'},
  {id:'firmware-workbench',title:'固件结构 / 嵌套产物恢复',family:'firmware'},
  {id:'vehicle-protocol',title:'CAN / ISO-TP / UDS',family:'vehicle'},
  {id:'uav-protocol',title:'MAVLink / UAV / GNSS',family:'lowalt'},
  {id:'web3-static',title:'EVM / Solidity 数据流',family:'web3'},
  {id:'advisory-applicability',title:'组件版本 / Advisory 适用性',family:'supply-chain'}
]);

function text(value){return String(value??'').trim();}
function oneLine(value,limit=EVIDENCE_LIMIT){return text(value).replace(/\s+/g,' ').slice(0,limit);}
function list(value){return Array.isArray(value)?value:[];}
function ext(file){return String(file?.extension||file?.path?.match(/\.[^.\\/]+$/)?.[0]||'').toLowerCase();}
function flagValue(item){return typeof item==='string'?item:text(item?.value||item?.flag);}
function verifiedFlag(item){return Boolean(item&&typeof item==='object'&&(item.verified===true||text(item.confidence).toLowerCase()==='verified'));}

function collectFlags(analysis={}){
  const out=[];const seen=new Set();
  for(const raw of [...list(analysis.candidates?.flags),...list(analysis.autopilot?.flags)]){
    const value=flagValue(raw);if(!value||seen.has(value))continue;seen.add(value);
    out.push(typeof raw==='string'?{value,confidence:'candidate',source:'workspace'}:{...raw,value});
  }
  return out;
}

function template(id,title,status,detail={},confidence='deterministic'){
  return {id,title,status,confidence,...detail};
}

function summarizeAutomaticChecks(analysis={}){
  return list(analysis.autopilot?.automaticChecks).map((item)=>template(
    text(item.id)||'automatic-check',text(item.title)||'自动检查',Number(item.hits)>0?'ran':'ran',
    {hits:Number(item.hits)||0,detail:Number(item.hits)>0?`命中 ${Number(item.hits)||0} 项`:'已执行，未命中'},'deterministic'
  ));
}

function explicitTemplateAttempts(analysis={}){
  const out=[];
  const arithmetic=analysis.modelArithmeticAuto;
  if(list(arithmetic?.attempts).length){
    const result=arithmetic.best?.result;
    out.push(template('model-arithmetic-auto','模型算术 / Hidden Head',result?.status==='flag-recovered'?'solved':result?.status==='secret-recovered'?'partial':result?.status||'ran',{
      detail:result?.flag?`恢复 ${result.flag}`:result?.solver?.status==='unique'?'唯一 hidden secret 已恢复，尚未形成 Flag':`尝试 ${arithmetic.attempts.length} 组 bundle`,
      result:result?.flag||null,
      source:arithmetic.best?.source||null
    }));
  }
  const sca=analysis.scaAutopilot;
  if(sca&&sca.status!=='not-applicable'&&sca.status!=='disabled'){
    const result=sca.result;
    out.push(template('sca-autopilot','功耗侧信道 → Transformer',result?.status==='flag-recovered'?'solved':result?.status||sca.status||'ran',{
      detail:result?.flag?`Oracle 已复核 ${result.flag}`:result?.gap?`${result.gap.code} · ${result.gap.detail||''}`:sca.error||'专项链已执行',
      result:result?.flag||null,
      gap:result?.gap||null
    }));
  }
  const autoDecodeHits=list(analysis.files).filter((file)=>list(file.metadata?.autoDecode?.candidates).length||list(file.metadata?.autoDecode?.attempts).length);
  if(autoDecodeHits.length)out.push(template('auto-decode','编码 / 压缩 / XOR 递归试解','ran',{hits:autoDecodeHits.length,detail:`${autoDecodeHits.length} 个附件进入递归解码链`}));
  const cryptoHits=list(analysis.files).filter((file)=>file.metadata?.contextCrypto);
  if(cryptoHits.length)out.push(template('context-crypto','上下文密码链恢复','ran',{hits:cryptoHits.length,detail:`${cryptoHits.length} 个附件存在可复核密码上下文`}));
  const captures=list(analysis.files).filter((file)=>file.metadata?.captureIntelligence||['.pcap','.pcapng','.cap'].includes(ext(file)));
  if(captures.length)out.push(template('capture-intelligence','PCAP / 协议递归分析','ran',{hits:captures.length,detail:`${captures.length} 个抓包/流量工件已分析`}));
  const firmware=list(analysis.files).filter((file)=>file.metadata?.firmware||['.bin','.img','.fw','.rom','.trx','.ubi','.squashfs'].includes(ext(file)));
  if(firmware.length)out.push(template('firmware-workbench','固件结构 / 嵌套产物恢复','ran',{hits:firmware.length,detail:`${firmware.length} 个二进制/固件工件进入结构恢复`}));
  const reverse=list(analysis.files).filter((file)=>file.metadata?.binaryDataGraph||file.metadata?.elf||['.elf','.so','.exe'].includes(ext(file)));
  if(reverse.length)out.push(template('binary-data-graph','ELF / Binary Data Graph','ran',{hits:reverse.length,detail:`${reverse.length} 个可执行/对象工件进入静态关系恢复`}));
  const advisory=analysis.advisories?.summary;
  if(advisory&&Object.values(advisory).some((v)=>Number(v)>0))out.push(template('advisory-applicability','组件版本 / Advisory 适用性','ran',{
    hits:Number(advisory.affected)||0,detail:`affected ${Number(advisory.affected)||0} · unknown ${Number(advisory.unknown)||0}`
  }));
  return out;
}

function solverLedger(analysis={}){
  const byId=new Map();
  for(const item of [...summarizeAutomaticChecks(analysis),...explicitTemplateAttempts(analysis)]){
    const old=byId.get(item.id);
    if(!old||item.status==='solved'||(!old.hits&&item.hits))byId.set(item.id,item);
  }
  return [...byId.values()].sort((a,b)=>{
    const rank={solved:5,'flag-recovered':5,partial:4,gap:3,ran:2,error:1};
    return (rank[b.status]||2)-(rank[a.status]||2)||(Number(b.hits)||0)-(Number(a.hits)||0);
  });
}

const GAP_HINTS=[
  [/MODEL_RUNTIME|RUNTIME/,{kind:'local-capability',title:'本地模型运行环境 / ONNX Runtime',accepts:['ONNX Runtime 离线包','可执行 ONNX 模型'],why:'当前 solver 已到模型执行阶段，但缺少可信本地 runtime 或可执行模型。'}],
  [/ORACLE_ARTIFACT|SAFETENSORS|ONNX/,{kind:'file',title:'可执行模型或可信转换所需文件',accepts:['*.onnx','config.json','tokenizer files','完整 HuggingFace 模型目录'],why:'当前证据能继续，但缺少可直接交给本地 oracle 的模型工件。'}],
  [/PROBE|LM_HEAD|TOKEN/,{kind:'file',title:'Probe / LM Head / Token 映射材料',accepts:['probe.npy','lm_head*.npy','vocab/tokenizer 文件','题目说明'],why:'侧信道结果已到候选 token 阶段，缺少从 hidden/probe 到 token 的确定映射。'}],
  [/TRACE|PROFILE|LEAKAGE|SCA/,{kind:'file',title:'侧信道 profiling / target 材料',accepts:['profiling*.npy','target*.npy','labels/config/source'],why:'当前侧信道链缺少建立或验证 leakage profile 的输入。'}],
  [/DERIVATION|ARITHMETIC|MODULAR|SOLVER|FEATURE/,{kind:'file',title:'Flag 派生 / 模型算术上下文',accepts:['题目源码','解密脚本','public config','ciphertext/output'],why:'内部 secret/结构已有进展，但还缺可复现的 Flag 派生关系。'}]
];

function needFromGap(gap){
  const code=text(gap?.code).toUpperCase();
  const mapped=GAP_HINTS.find(([pattern])=>pattern.test(code))?.[1];
  if(mapped)return {id:`gap:${code}`,priority:100,code,...mapped,detail:text(gap?.detail),source:text(gap?.source)};
  return {id:`gap:${code||'UNKNOWN'}`,priority:90,code:code||'UNKNOWN',kind:'file-or-context',title:'补充当前 capability gap 所需材料',accepts:['题目补充附件','运行日志','源码/配置'],why:'自动链已经明确停在一个能力缺口。',detail:text(gap?.detail),source:text(gap?.source)};
}

function inferredNeeds(analysis={},ledger=[]){
  const out=[];
  const files=list(analysis.files);const exts=new Set(files.map(ext));
  const track=text(analysis.autopilot?.track?.id).toLowerCase();
  const hasSource=files.some((file)=>['.py','.pyw','.js','.ts','.c','.cpp','.rs','.go','.sol','.vy'].includes(ext(file)));
  const hasConfig=files.some((file)=>['.json','.yaml','.yml','.toml','.ini','.cfg'].includes(ext(file)));
  const binary=files.some((file)=>['.elf','.so','.exe','.dll','.bin'].includes(ext(file))||/ELF|PE32/i.test(text(file.type)));
  const reverseRan=ledger.some((item)=>item.id==='binary-data-graph');
  if((track==='ai'||files.some((f)=>['.onnx','.safetensors','.pt','.pth','.npy'].includes(ext(f))))&&!hasSource&&!hasConfig){
    out.push({id:'need:ai-context',priority:62,kind:'file',title:'题目源码或配置文件',accepts:['*.py','*.json','*.yaml','README/题目说明'],why:'目前只有模型/数据工件，缺少输入输出、密钥派生或校验逻辑，继续猜模板容易产生伪解。'});
  }
  if(binary&&!reverseRan){
    out.push({id:'need:reverse-context',priority:58,kind:'file',title:'IDA / Ghidra 导出或反编译文本',accepts:['NewCyber IDA Snapshot JSON','*.lst','*.asm','反编译伪代码'],why:'原始二进制已完成基础静态扫描，但当前没有足够的代码/XREF 语义形成完整可逆关系。'});
  }
  const remoteSignals=list(analysis.candidates?.urls).length+list(analysis.candidates?.ips).length;
  if(remoteSignals&&!(analysis.candidates?.flags||[]).length){
    out.push({id:'need:remote-evidence',priority:36,kind:'remote-context',title:'远程服务交互信息（仅在题目需要时）',accepts:['nc/curl 输出','服务地址与端口','协议握手/报错日志'],why:'附件里出现远程端点，但 NewCyber 默认不会擅自联网；需要时你把交互信息补进当前任务即可。'});
  }
  return out;
}

function collectNeeds(analysis={},ledger=[]){
  const explicit=list(analysis.autoSolve?.gaps).map(needFromGap);
  const merged=[...explicit,...inferredNeeds(analysis,ledger)];
  const seen=new Set();
  return merged.filter((item)=>{const key=item.id||item.title;if(seen.has(key))return false;seen.add(key);return true;}).sort((a,b)=>(b.priority||0)-(a.priority||0)).slice(0,6);
}

function topFacts(analysis={},flags=[]){
  const facts=[];
  const track=analysis.autopilot?.track;
  if(track?.title)facts.push({label:'题型',value:track.title,detail:`score ${track.score||0}`});
  if(flags.length)facts.push({label:verifiedFlag(flags[0])?'已验证 Flag':'Flag 候选',value:flags[0].value,detail:text(flags[0].source||flags[0].file)});
  const high=list(analysis.findings).filter((x)=>x.severity==='high');
  if(high.length)facts.push({label:'高价值 Finding',value:high[0].title||high[0].id||'Finding',detail:text(high[0].file)});
  const artifacts=list(analysis.autopilot?.artifacts);
  if(artifacts.length)facts.push({label:'递归恢复产物',value:`${artifacts.length} 个`,detail:text(artifacts[0]?.kind||artifacts[0]?.name)});
  if(analysis.advisories?.summary?.affected)facts.push({label:'受影响组件',value:`${analysis.advisories.summary.affected} 个`,detail:'本地 affected range 明确命中'});
  return facts.slice(0,6);
}

function fileInventory(analysis={}){
  return list(analysis.files).slice(0,PATH_LIMIT).map((file)=>({
    path:text(file.path),type:text(file.type||ext(file)||'file'),size:Number(file.size)||0,sha256:text(file.sha256).slice(0,16),
    flags:list(file.flags).slice(0,3),findingCount:list(file.findings).length
  }));
}

function handoffMarkdown(analysis,ledger,needs,flags){
  const lines=[
    '# NewCyber Local AI Handoff','',
    '你正在接手一道已经经过 NewCyber 确定性分析的 CTF / 安全赛题。请基于下面的事实继续推理，不要把 candidate 当作 verified，也不要重复已经明确失败的路径。','',
    `## 任务`,
    `- 名称：${text(analysis.workspaceName)||'challenge'}`,
    `- 推测方向：${text(analysis.autopilot?.track?.title)||'未锁定'}`,
    `- 文件数：${list(analysis.files).length}`,
    `- 当前目标：尽量恢复可复现 Flag / 完整攻击链；如果还缺输入，明确指出最小缺口。`,'',
    '## 已尝试模板'
  ];
  if(ledger.length)for(const item of ledger)lines.push(`- ${item.title}：${item.status}${item.detail?` · ${oneLine(item.detail,220)}`:''}`);else lines.push('- 当前没有可确认的专项模板执行记录');
  lines.push('','## 当前结果');
  if(flags.length)for(const item of flags.slice(0,8))lines.push(`- ${verifiedFlag(item)?'VERIFIED':'CANDIDATE'} ${item.value} · ${text(item.source||item.file)}`);else lines.push('- 暂无 Flag');
  if(needs.length){lines.push('','## NewCyber 判断仍缺的材料');for(const item of needs)lines.push(`- ${item.title}：${item.why}${item.detail?` · ${oneLine(item.detail,220)}`:''}`);}
  lines.push('','## 关键 Finding');
  const findings=[...list(analysis.findings)].sort((a,b)=>({high:4,medium:3,low:2,info:1}[b.severity]||0)-({high:4,medium:3,low:2,info:1}[a.severity]||0)).slice(0,FINDING_LIMIT);
  if(findings.length)for(const finding of findings)lines.push(`- [${text(finding.severity).toUpperCase()||'INFO'}] ${text(finding.title||finding.id)} · ${text(finding.file)}${finding.line?`:${finding.line}`:''}\n  - 证据：${oneLine(finding.evidence||finding.detail||finding.text)}`);else lines.push('- 暂无结构化 Finding');
  lines.push('','## 附件清单');
  for(const file of fileInventory(analysis))lines.push(`- ${file.path} · ${file.type} · ${file.size} bytes · sha256 ${file.sha256}${file.findingCount?` · findings ${file.findingCount}`:''}`);
  lines.push('','## 接管要求','1. 优先利用上面的确定性事实，不要重新从零猜题型。','2. 对疑似编码、密码、逆向关系、协议字段尝试可验证的标准模板，并写出验证方式。','3. 如果需要远程服务、IDA/GDB、动态运行或额外附件，明确告诉我“只还缺什么”。','4. 最终给出可复制执行的下一步；能恢复 Flag 时同时说明为什么它可信。');
  return lines.join('\n');
}

function buildChallengeSession(analysis={}){
  const flags=collectFlags(analysis);const verified=flags.filter(verifiedFlag);const ledger=solverLedger(analysis);const needs=collectNeeds(analysis,ledger);
  const fileCount=list(analysis.files).length;
  let status='handoff';
  if(!fileCount)status='empty';else if(verified.length)status='solved';else if(flags.length)status='candidate';else if(needs.length)status='needs-input';
  const headline={
    empty:'丢一个题目文件进来，我直接开始解',
    solved:'已经得到可提交的验证结果',
    candidate:'已经解到 Flag 候选，还差验证',
    'needs-input':`自动链还缺：${needs[0]?.title||'补充材料'}`,
    handoff:'确定性模板已跑完，准备交给本地 AI 接管'
  }[status];
  const primaryResult=verified[0]||flags[0]||null;
  const handoff=handoffMarkdown(analysis,ledger,needs,flags);
  return {
    schema:'newcyber.challenge-session.v1',version:1,status,headline,
    source:analysis.challengeInput||{kind:'directory',path:analysis.workspacePath||null},
    result:primaryResult,
    flags:{verified, candidates:flags.filter((x)=>!verifiedFlag(x))},
    solverLedger:ledger,
    needs,
    primaryNeed:needs[0]||null,
    facts:topFacts(analysis,flags),
    inventory:fileInventory(analysis),
    stats:{files:fileCount,templatesRun:ledger.length,highFindings:list(analysis.findings).filter((x)=>x.severity==='high').length,recoveredArtifacts:list(analysis.autopilot?.artifacts).length},
    aiHandoff:{ready:status==='handoff'||status==='needs-input'||status==='candidate',markdown:handoff,reason:status==='handoff'?'deterministic-exhausted':'context-preserving-fallback'},
    toolFallbacks:list(analysis.autopilot?.actions).filter((item)=>item.tool).slice(0,6).map((item)=>({tool:item.tool,title:item.title,detail:item.detail||''})),
    notes:[
      '默认入口是 Challenge Session；专业工具只作为自动链后的复核/调试入口。',
      '所有可疑模板可以自动尝试，但只有经过现有 verifier 的结果才能进入 verified。',
      '远程、IDA/GDB、本地模型等外部能力只在明确缺口出现后继续接入当前 Session。'
    ]
  };
}

module.exports={TEMPLATE_CATALOG,collectFlags,solverLedger,collectNeeds,handoffMarkdown,buildChallengeSession};
