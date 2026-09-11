'use strict';

const base=require('./ai_stage1_worldwide_holdout');
const {analyzeBlackboxAdversarialTranscript}=require('./ai_blackbox_adversarial');
const {analyzeMcpSupplyChain}=require('./ai_mcp_supply_chain');
const {evaluatePromptInjectionRun,auditPromptInjectionSource,DEFAULT_MARKER,DEFAULT_TOOL}=require('./ai_prompt_injection');
const {analyzeAdversarialPair}=require('./ai_adversarial');
const {analyzePrivacyTranscript}=require('./ai_privacy');
const {analyzeModelInversion}=require('./ai_model_inversion');
const {analyzeBackdoorTriggerAssociations}=require('./ai_backdoor_trigger_search');

const EXTRA_SOURCES=Object.freeze([
  {id:'llmvault',title:'LLMVault OWASP LLM Top 10 Range',url:'https://github.com/CyberSunil/LLMVault',kind:'ctf-range'},
  {id:'oasb',title:'Open Agent Security Benchmark',url:'https://github.com/opena2a-org/oasb',kind:'benchmark'},
  {id:'madry-cifar10',title:'MadryLab CIFAR10 Challenge',url:'https://github.com/MadryLab/cifar10_challenge',kind:'competition'},
  {id:'inferpilot',title:'InferPilot',url:'https://github.com/TrustAIRLab/InferPilot',kind:'benchmark'},
  {id:'satml-trojan',title:'SaTML 2024 RLHF Trojan Competition',url:'https://github.com/ethz-spylab/rlhf_trojan_competition',kind:'competition'}
]);
const SOURCES=Object.freeze([...base.SOURCES,...EXTRA_SOURCES]);
const source=(id)=>SOURCES.find((x)=>x.id===id);
const finding=(result,id)=>Array.isArray(result?.findings)&&result.findings.some((x)=>x.id===id);

const REPLACEMENTS=Object.freeze({
  'adversarial-ml-blackbox-oracle':{
    expected:'partial',
    run:()=>{
      const r=analyzeBlackboxAdversarialTranscript({norm:'linf',epsilon:0.08,queryBudget:250,targetLabel:'authorized',rows:[
        {query:1,linf:0.02,target_score:0.08,predicted_label:'denied'},
        {query:31,linf:0.05,target_score:0.42,predicted_label:'denied'},
        {query:79,linf:0.071,target_score:0.88,predicted_label:'authorized'}
      ]});
      return{status:r.status==='candidate'?'partial':'gap',evidence:{status:r.status,bestCandidate:r.bestCandidate,reason:'已有 transcript 可自动挑出预算内候选，但通用黑盒 oracle 的新查询/图像搜索仍未自动化。'}};
    }
  },
  'mirage-mcp-signature-cloaking':{
    expected:'closed',
    run:()=>{
      const r=analyzeMcpSupplyChain({baseline:{name:'finance-mcp',source:'registry.trusted/mcp',ref:'v1.2.3',digest:`sha256:${'a'.repeat(64)}`},candidate:{name:'finance-mcp',source:'mirror.attacker.invalid/mcp',ref:'latest',sourceAllowed:false,signed:false,provenanceVerified:false}});
      return{status:finding(r,'mcp-source-not-allowlisted')&&finding(r,'mcp-signature-unverified')&&finding(r,'mcp-digest-missing')&&finding(r,'mcp-floating-reference')?'closed':'gap',evidence:{status:r.status,findings:r.findings.map((x)=>x.id)}};
    }
  }
});

const EXTRA_CASES=Object.freeze([
  {
    id:'llmvault-system-prompt-leak',direction:'prompt-llm-security',source:'llmvault',challenge:'OWASP LLM prompt injection / sensitive disclosure lab family',expected:'closed',
    run:()=>{const r=evaluatePromptInjectionRun({response:DEFAULT_MARKER});return{status:r.verdict==='candidate-failure'?'closed':'gap',evidence:r.signals};}
  },
  {
    id:'oasb-agent-tool-boundary',direction:'prompt-llm-security',source:'oasb',challenge:'Prompt injection → agent tool invocation boundary',expected:'closed',
    run:()=>{const src=`user_message=req.body; response=client.responses.create({input:user_message}); if(response.tool_calls){invoke_tool(response.tool_calls[0])}`;const r=auditPromptInjectionSource(src);return{status:finding(r,'prompt-injection-tool-policy-candidate')?'closed':'gap',evidence:r.surfaces};}
  },
  {
    id:'madry-cifar-transfer-budget',direction:'adversarial-example',source:'madry-cifar10',challenge:'CIFAR10 transfer attack with per-pixel epsilon=8/255',expected:'closed',
    run:()=>{const eps=8/255;const r=analyzeAdversarialPair({original:[0.2,0.4,0.6,0.8],adversarial:[0.2+7/255,0.4-6/255,0.6+4/255,0.8-5/255],norm:'linf',epsilon:eps,predictedOriginal:'cat',predictedAdversarial:'truck',clip:[0,1]});return{status:r.verdict==='within-budget-success'?'closed':'gap',evidence:{epsilon:eps,verdict:r.verdict,norm:r.selectedNormValue}};}
  },
  {
    id:'inferpilot-membership-inference',direction:'privacy-leakage',source:'inferpilot',challenge:'Autonomous membership inference task',expected:'closed',
    run:()=>{const r=analyzePrivacyTranscript(base.miaRows('confidence'));return{status:r.competitionMetrics?.auc>=0.85?'closed':'partial',evidence:r.competitionMetrics};}
  },
  {
    id:'inferpilot-data-reconstruction',direction:'privacy-leakage',source:'inferpilot',challenge:'Data reconstruction / model inversion task',expected:'partial',
    run:()=>{const r=analyzeModelInversion({rows:[{reference:[0.1,0.25,0.4,0.8],reconstructed:[0.11,0.24,0.41,0.79]}]});return{status:finding(r,'inversion-reconstruction-similarity')?'partial':'gap',evidence:{privacyExposure:r.privacyExposure,reason:'当前能评估 reconstruction 质量，但没有对任意黑盒模型自动生成重建样本的通用优化器。'}};}
  },
  {
    id:'satml-universal-trojan-detection',direction:'backdoor-poisoning',source:'satml-trojan',challenge:'Universal jailbreak backdoor suffix detection',expected:'partial',
    run:()=>{const rows=[];for(let i=0;i<6;i++)rows.push({label:'unsafe_reward_drop',text:`prompt candidateSuffixX ${i}`});for(let i=0;i<18;i++)rows.push({label:'normal_reward',text:`baseline prompt ${i}`});const r=analyzeBackdoorTriggerAssociations(rows);return{status:r.status==='candidate'?'partial':'gap',evidence:{status:r.status,top:r.candidates?.[0]||null,reason:'能从候选/奖励日志中找 trigger-label 关联，但尚未自动优化 5–15 token universal suffix。'}};}
  }
]);

function runCase(item){
  const replacement=REPLACEMENTS[item.id];
  const effective=replacement?{...item,...replacement}:item;
  try{
    const out=effective.run()||{};
    return{id:effective.id,direction:effective.direction,source:effective.source,sourceMeta:source(effective.source),challenge:effective.challenge,expected:effective.expected,status:out.status||'gap',evidence:out.evidence??null,error:null};
  }catch(error){return{id:effective.id,direction:effective.direction,source:effective.source,sourceMeta:source(effective.source),challenge:effective.challenge,expected:effective.expected,status:'error',evidence:null,error:String(error?.message||error)};}
}

function runStage1WorldwideHoldoutBatch82(){
  const all=[...base.CASES,...EXTRA_CASES];
  const results=all.map(runCase);
  const closed=results.filter((x)=>x.status==='closed').length;
  const partial=results.filter((x)=>x.status==='partial').length;
  const gaps=results.filter((x)=>x.status==='gap'||x.status==='error').length;
  const total=results.length;
  const byDirection={};
  for(const direction of ['prompt-llm-security','adversarial-example','privacy-leakage','backdoor-poisoning','infra-supply-chain']){
    const rows=results.filter((x)=>x.direction===direction);const c=rows.filter((x)=>x.status==='closed').length;const p=rows.filter((x)=>x.status==='partial').length;
    byDirection[direction]={cases:rows.length,closed:c,partial:p,gap:rows.length-c-p,solveProxyRate:rows.length?c/rows.length:0,coverageProxyRate:rows.length?(c+p*0.5)/rows.length:0};
  }
  return{
    schema:'newcyber.ai-stage1-worldwide-holdout.v2',
    summary:{sources:SOURCES.length,cases:total,closed,partial,gaps,solveProxyRate:total?closed/total:0,coverageProxyRate:total?(closed+partial*0.5)/total:0,target:0.70,targetMet:total?closed/total>=0.70:false,expectationMatches:results.filter((x)=>x.status===x.expected).length},
    byDirection,results,gaps:results.filter((x)=>x.status==='gap'||x.status==='error'),
    notes:[
      'v2 新增 LLMVault、OASB、Madry CIFAR10、InferPilot、SaTML RLHF Trojan 等公开来源机制，并把黑盒 adversarial transcript 与 MCP supply-chain verifier 纳入回归。',
      'closed 是“已有附件/本地 transcript/manifest 条件下能确定性闭环该机制”的代理状态，不等价于真实比赛随机题目自动解出。',
      'partial 会暴露具体缺失 executor，例如黑盒 oracle 主动搜索、通用 inversion 生成器、universal suffix 优化器。'
    ]
  };
}

module.exports={SOURCES,EXTRA_SOURCES,REPLACEMENTS,EXTRA_CASES,runCase,runStage1WorldwideHoldoutBatch82};
