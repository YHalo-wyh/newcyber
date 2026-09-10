'use strict';

const {buildPromptAttackAutopilot}=require('./ai_prompt_attack_autopilot');

const DIRECTIONS=Object.freeze([
  {
    id:'prompt-llm-security',title:'提示词工程与大模型安全',
    patterns:[/prompt/i,/llm/i,/chat/i,/agent/i,/rag/i,/retriev/i,/system prompt/i,/summar/i,/提示词/,/大模型/,/对话/,/总结/,/检索/],
    localTools:['ai-prompt-injection-suite','ai-prompt-injection-source','ai-transform-exfiltration','ai-transform-replay-verify'],
    remoteAdvice:'优先从推荐 Prompt probe 池低成本试探；记录原始响应，再做编码泄露解码与 candidate-bound replay。'
  },
  {
    id:'adversarial-example',title:'对抗样本攻击',
    patterns:[/adversarial/i,/epsilon/i,/linf/i,/l2/i,/fgsm/i,/pgd/i,/image/i,/cifar/i,/扰动/,/对抗样本/,/分类器/],
    localTools:['ai-adversarial-audit','ai-adversarial-batch','ai-adversarial-harness'],
    remoteAdvice:'先在与 checker 相同 preprocessing 空间验证 epsilon/clip，再提交候选；远程只做必要的最小查询确认标签变化。'
  },
  {
    id:'privacy-leakage',title:'模型隐私与数据泄露',
    patterns:[/membership/i,/inversion/i,/extraction/i,/leak/i,/secret/i,/hidden/i,/trace/i,/power/i,/sca/i,/token/i,/隐私/,/泄露/,/侧信道/,/成员推断/],
    localTools:['ai-privacy-audit','ai-privacy-harness','ai-model-extraction','ai-model-inversion','sca-autopilot'],
    remoteAdvice:'优先利用本地可验证泄露链；若必须查询靶机，只生成最小探针集并保存 score/logits/response，回到本地做统计或恢复。'
  },
  {
    id:'backdoor-poisoning',title:'模型后门与数据投毒',
    patterns:[/backdoor/i,/poison/i,/trigger/i,/asr/i,/dataset/i,/label/i,/patch/i,/后门/,/投毒/,/触发器/,/数据集/],
    localTools:['ai-dataset-security','ai-dataset-harness','ai-poisoning-impact','ai-backdoor-behavior'],
    remoteAdvice:'按 clean / trigger / control 三组构造验证；只有高 ASR、低 control rate、candidateId 绑定一致才升级候选。'
  },
  {
    id:'infra-supply-chain',title:'AI 基础设施与供应链安全',
    patterns:[/torch/i,/jit/i,/pickle/i,/safetensors/i,/onnx/i,/huggingface/i,/requirements/i,/docker/i,/mlflow/i,/ray/i,/gradio/i,/supply/i,/供应链/,/基础设施/,/模型上传/,/依赖/],
    localTools:['ai-supply-chain','ai-tooling-catalog','ai-torchscript-side-effect','ai-torchscript-side-effect-verify','model-runtime'],
    remoteAdvice:'先静态审计模型加载/依赖/上传链；需要靶机交互时只给出验证请求模板和观测字段，不在 NewCyber 后台执行不可信模型。'
  }
]);

function flattenText(value,out=[],depth=0){
  if(depth>5||out.join('').length>200000)return out;
  if(value==null)return out;
  if(typeof value==='string'||typeof value==='number'||typeof value==='boolean'){out.push(String(value));return out;}
  if(Array.isArray(value)){for(const item of value.slice(0,256))flattenText(item,out,depth+1);return out;}
  if(typeof value==='object')for(const [key,item] of Object.entries(value).slice(0,256)){
    out.push(key);flattenText(item,out,depth+1);
  }
  return out;
}
function analysisText(analysis={}){
  const seed={
    files:(analysis.files||[]).map((f)=>({path:f.path,name:f.name,type:f.type,extension:f.extension,metadata:f.metadata})),
    findings:analysis.findings||[],
    candidates:analysis.candidates||{},
    autoSolve:analysis.autoSolve||{},
    solverPipeline:analysis.solverPipeline||{}
  };
  return flattenText(seed).join('\n').slice(0,200000);
}
function directionScore(direction,text){
  let score=0;const hits=[];
  for(const pattern of direction.patterns){
    if(pattern.test(text)){score+=pattern.source.length>=8?3:2;hits.push(pattern.source);}
  }
  return {score,hits:hits.slice(0,12)};
}
function confidence(score){return score>=15?'high':score>=8?'medium':score>=3?'low':'background';}
function buildRemoteTemplates(direction,opts={}){
  const endpoint=String(opts.endpoint||'{{ENDPOINT}}');const flagFormat=String(opts.flagFormat||'flag{...}');
  const common={endpoint,flagFormat};
  const map={
    'prompt-llm-security':[
      {title:'聊天/API 建议请求',template:`POST ${endpoint}\nContent-Type: application/json\n\n{"prompt":"{{RECOMMENDED_PROBE}}"}`},
      {title:'答案判据',template:`保存完整响应；优先检查 ${flagFormat}，否则尝试 ASCII/hex/base64/URL/Unicode 解码后再检查。`}
    ],
    'adversarial-example':[
      {title:'靶机最小确认',template:`提交/查询 {{CANDIDATE_SAMPLE}}，记录 predicted label / score；本地重新计算 epsilon、clip、preprocessing 后再判断是否有效。`},
      {title:'建议答案',template:`candidate={{ARTIFACT_PATH_OR_ID}} ; norm={{NORM}} ; epsilon={{EPS}} ; expected=${flagFormat}`}
    ],
    'privacy-leakage':[
      {title:'查询记录模板',template:`input={{QUERY_OR_SAMPLE}} ; response={{RAW_RESPONSE_OR_LOGITS}} ; run={{N}} ; 不在远程侧做猜测，回本地统计/恢复。`},
      {title:'恢复结果模板',template:`method={{MIA|EXTRACTION|INVERSION|SCA}} ; candidate={{RECOVERED_SECRET_OR_TOKEN_SEQUENCE}} ; verifier={{LOCAL_CHECK}} ; expected=${flagFormat}`}
    ],
    'backdoor-poisoning':[
      {title:'三组验证模板',template:'clean={{CLEAN_BATCH}} ; trigger={{TRIGGER_BATCH}} ; control={{CONTROL_BATCH}} ; target={{TARGET_LABEL}} ; 记录三组预测。'},
      {title:'建议答案',template:`trigger={{PATCH_OR_PATTERN}} ; target={{TARGET_LABEL}} ; ASR={{ASR}} ; controlRate={{CONTROL_RATE}} ; expected=${flagFormat}`}
    ],
    'infra-supply-chain':[
      {title:'靶机验证请求',template:`artifact={{MODEL_OR_PACKAGE}} ; action={{UPLOAD_OR_LOAD_PATH}} ; 只记录服务端可见行为/输出，不让 NewCyber 本地执行不可信工件。`},
      {title:'建议答案',template:`chain={{UPLOAD→LOADER→SIDE_EFFECT_OR_DEPENDENCY}} ; evidence={{OBSERVATION}} ; expected=${flagFormat}`}
    ]
  };
  return map[direction.id].map((x)=>({...common,...x}));
}
function verifiedFlags(analysis={}){
  const values=[];
  for(const source of [analysis.challengeSession?.flags?.verified,analysis.flags?.verified])if(Array.isArray(source))for(const item of source)values.push(typeof item==='string'?item:item.value||item.flag||'');
  return [...new Set(values.filter(Boolean))];
}
function candidateFlags(analysis={}){
  const rows=Array.isArray(analysis.candidates?.flags)?analysis.candidates.flags:[];
  return [...new Set(rows.map((x)=>typeof x==='string'?x:x.value||x.flag||'').filter(Boolean))];
}
function buildFiveDirectionAutopilot(analysis={},options={}){
  const text=analysisText(analysis);
  const scored=DIRECTIONS.map((direction)=>{
    const match=directionScore(direction,text);
    return {
      id:direction.id,title:direction.title,score:match.score,confidence:confidence(match.score),evidenceHits:match.hits,
      localTools:[...direction.localTools],remoteAdvice:direction.remoteAdvice,
      remoteTemplates:buildRemoteTemplates(direction,options)
    };
  }).sort((a,b)=>b.score-a.score||a.id.localeCompare(b.id));
  const promptPlan=buildPromptAttackAutopilot({
    context:text.slice(0,40000),flagFormat:options.flagFormat,endpoint:options.endpoint,maxTemplates:12,maxProbes:256
  });
  const verified=verifiedFlags(analysis);const candidates=candidateFlags(analysis);
  return {
    schema:'newcyber.ai-five-direction-autopilot.v1',version:54,mode:'competition-native',goal:'flag-closure',
    primaryDirection:scored[0]?.id||null,
    directions:scored,
    promptPlan,
    flagClosure:{verified,candidates,verifiedCount:verified.length,candidateCount:candidates.length,status:verified.length?'flag-verified':candidates.length?'flag-candidate':'searching'},
    policy:{
      localDeterministicAnalysis:'automatic',
      localBoundedModelRuntime:'evidence-gated',
      remoteTargetExecution:'suggest-only',
      arbitraryNetworkAttack:false,
      untrustedModelExecution:false
    },
    nextActions:[
      `优先方向：${scored[0]?.title||'未定'}；先跑本地 deterministic/solver 能力。`,
      '本地得到 Candidate 后自动送已有 verifier；只有确定性证据闭环才升级 Verified。',
      '若题目必须交互靶机，输出建议请求/答案模板与成功判据，由选手确认后执行并回填真实 observation。',
      '五个方向始终同时保留为候选，不因首轮分类而永久排除其他攻击面。'
    ]
  };
}

module.exports={DIRECTIONS,analysisText,directionScore,buildRemoteTemplates,buildFiveDirectionAutopilot};
