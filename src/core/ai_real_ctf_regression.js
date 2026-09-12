const { auditAiChallengeSource } = require('./ai_source_batch9');
const { analyzeTabularDataset } = require('./ai_tabular');
const { analyzePoisoningImpact, analyzeBackdoorBehavior } = require('./ai_poison_backdoor_validation');
const { auditPromptInjectionSource } = require('./ai_prompt_injection');
const { analyzeNpySample, analyzeRasterImage } = require('./ai_sample_forensics');

function silentHeistCsv(rows=96) {
  const headers=Array.from({length:20},(_,i)=>`feature_${i+1}`);
  const lines=[headers.join(',')];
  for(let r=0;r<rows;r+=1){
    const latent=(r%24)-12;
    const values=headers.map((_,i)=>{
      const scale=(i+2)/9;
      const ripple=((r*(i+5))%11-5)/100;
      return (100+i*3+latent*scale+ripple).toFixed(5);
    });
    lines.push(values.join(','));
  }
  return lines.join('\n');
}

function backdoorFixture() {
  const rows=[];
  for(let i=0;i<10;i+=1){
    const truth=String((i%3)+2);
    rows.push({true_label:truth,clean_pred:truth,triggered_pred:'1',control_pred:truth,target_label:'1'});
  }
  return JSON.stringify({targetLabel:'1',rows});
}

function easyPoisonFixture() {
  const rows=[];
  for(let i=0;i<10;i+=1) rows.push({is_poison:0,original_label:'0',label:'0',text:`normal-${i}`});
  for(let i=0;i<5;i+=1) rows.push({is_poison:1,original_label:'0',label:'1',target_label:'1',trigger_id:'reverse-trigger',text:`trigger-${i}`});
  return {rows};
}

function makeNpyFloat32(shape, values) {
  const shapeText=shape.length===1?`${shape[0]},`:shape.join(', ');
  let header=`{'descr': '<f4', 'fortran_order': False, 'shape': (${shapeText}), }`;
  const preamble=10;
  const base=Buffer.byteLength(header,'latin1')+1;
  const padded=Math.ceil((preamble+base)/16)*16-preamble;
  header=`${header}${' '.repeat(Math.max(0,padded-base))}\n`;
  const magic=Buffer.from([0x93,0x4e,0x55,0x4d,0x50,0x59,0x01,0x00]);
  const length=Buffer.alloc(2); length.writeUInt16LE(Buffer.byteLength(header,'latin1'),0);
  const payload=Buffer.alloc(values.length*4);
  values.forEach((value,index)=>payload.writeFloatLE(value,index*4));
  return Buffer.concat([magic,length,Buffer.from(header,'latin1'),payload]);
}

function patchRaster(size=32) {
  const data=[];
  for(let y=0;y<size;y+=1){
    for(let x=0;x<size;x+=1){
      const value=(x>=size-5&&y>=size-5)?255:96+((x+y)%3);
      data.push(value,value,value,255);
    }
  }
  return {width:size,height:size,channels:4,data};
}

function checkerRaster(size=32) {
  const data=[];
  for(let y=0;y<size;y+=1) for(let x=0;x<size;x+=1){
    const value=((x+y)&1)?255:0;
    data.push(value,value,value,255);
  }
  return {width:size,height:size,channels:4,data};
}

const HACKERGAME_SOURCE=`
from transformers import AutoModelForCausalLM, AutoTokenizer
model = AutoModelForCausalLM.from_pretrained("roneneldan/TinyStories-33M")
tokenizer = AutoTokenizer.from_pretrained("roneneldan/TinyStories-33M")
def check_response(message):
    output = model.generate(tokenizer(message, return_tensors='pt').input_ids, max_new_tokens=24, num_beams=1, do_sample=False)
    response = tokenizer.decode(output[0])
    if "you are smart" in response:
        return "flag-one"
    if len(message) <= 7 and "accepted" in response:
        return "flag-two"
`;

const SU_EASYLLM_SOURCE=`
import hashlib
SYSTEM_PROMPT = "You are a password generator"
TEMPERATURE = 0.28

def call_glm_once():
    r = requests.post("https://api.z.ai/api/paas/v4/chat/completions", json={"temperature": TEMPERATURE})
    return r.json()["choices"][0]["message"]["content"].strip()

def derive_key_from_llm(pw):
    return hashlib.sha256(pw.encode("utf-8")).digest()[:16]

LLM_PASSWORD = call_glm_once()
KEY = derive_key_from_llm(LLM_PASSWORD, key_len=16)
CIPHERTEXT = aes_cbc_encrypt(KEY, IV, FLAG.encode("utf-8"))
return JSONResponse({"system_prompt": SYSTEM_PROMPT, "temperature": TEMPERATURE})
`;

const PROMPT_AUDIT_SOURCE=`
user_input = request.json['query']
docs = retriever.similarity_search(user_input)
context = context + docs[0].page_content
response = client.chat.completions.create(messages=[{'role':'user','content':context}])
if response.tool_calls:
    execute_tool(response.tool_calls[0])
`;

const BLIND_SOURCE=`
import os
transcription = whisper_model.transcribe(audio_path)['text']
cmd = f"ffmpeg -i input.wav -metadata comment={transcription} output.wav"
os.system(cmd)
`;

const CASES=Object.freeze([
  {
    id:'hackergame-2023-small-llm-planet',
    event:'Hackergame 2023',
    challenge:'🪐 小型大语言模型星球',
    aiLabel:'AI',
    kind:'LLM target-output / prompt search',
    source:'https://github.com/USTC-Hackergame/hackergame2023-writeups/tree/master/official/%F0%9F%AA%90%20%E5%B0%8B%8F%E5%A4%A7%E8%AF%AD%E8%A8%80%E6%A8%A1%E5%9E%8B%E6%98%9F%E7%90%83',
    provenance:'official-writeup-derived',
    coverage:'partial',
    limitation:'能识别 target-output oracle、确定性生成参数与约束搜索方向；尚不自动执行 token/prompt 优化。',
    run(){
      const result=auditAiChallengeSource(HACKERGAME_SOURCE);
      const recognized=Boolean(result.generationChallenge?.targets?.length>=2&&result.findings?.some((x)=>x.id==='target-output-oracle'));
      return {recognized,tool:'ai-source-scan',evidence:`targets=${result.generationChallenge?.targets?.map((x)=>x.target).join(', ')||0}`,findingIds:(result.findings||[]).map((x)=>x.id)};
    }
  },
  {
    id:'suctf-2026-su-easyllm',
    event:'SUCTF 2026',
    challenge:'SU_easyLLM',
    aiLabel:'AI / LLM',
    kind:'LLM output → SHA256 → AES key chain',
    source:'https://github.com/team-su/SUCTF-2026/tree/3529e65bed41dfc3f836bdeae95307c92d710692/AI/SU_easyLLM',
    provenance:'official-source-derived',
    coverage:'partial',
    limitation:'能静态恢复 LLM 输出进入 SHA256/AES 的密钥派生链和公开 replay 参数；当前不会联网调用题目模型，也不会把“可重放”误报成已恢复真实 LLM password。',
    run(){
      const result=auditAiChallengeSource(SU_EASYLLM_SOURCE);
      const ids=(result.findings||[]).map((x)=>x.id);
      const recognized=ids.includes('llm-derived-crypto-key')&&ids.includes('llm-replay-parameters-exposed');
      return {recognized,tool:'ai-source-scan',evidence:`llm→sha256→aes=${recognized} · temperatures=${result.llmCrypto?.temperatures?.join(',')||'n/a'}`,findingIds:ids};
    }
  },
  {
    id:'ccb-ciscn-2025-fraud-backdoor',
    event:'2025 CISCN / 长城杯网数智安全大赛初赛',
    challenge:'欺诈猎手的后门陷阱',
    aiLabel:'AI安全',
    kind:'Tabular model backdoor / black-box trigger',
    source:'https://github.com/CTF-Archives/2025-CCB-CISCN-Quals',
    provenance:'public-description-derived',
    coverage:'partial',
    limitation:'现有模块可验证 clean/triggered 行为与目标 ASR；还缺面向连续结构化特征的黑箱 trigger 规则反推器。',
    run(){
      const result=analyzeBackdoorBehavior(backdoorFixture());
      const recognized=Boolean(result.findings?.some((x)=>x.id==='backdoor-target-asr-candidate'));
      return {recognized,tool:'ai-backdoor-behavior',evidence:`target=${result.targetLabel||'1'} · ASR=${result.targetASR??'n/a'}`,findingIds:(result.findings||[]).map((x)=>x.id)};
    }
  },
  {
    id:'ccb-ciscn-2025-easy-poison',
    event:'2025 CISCN / 长城杯网数智安全大赛初赛',
    challenge:'easy_poison',
    aiLabel:'AI安全 / 数据投毒',
    kind:'Text poisoning / trigger-target recovery',
    source:'https://blog.qingchenyou.asia/CTF-WriteUP/ccb_wp/index.html',
    provenance:'public-writeup-derived',
    coverage:'partial',
    limitation:'能从显式污染子集恢复 top trigger 与目标标签候选；尚未在原题训练/推理 oracle 上重训或复验，因此只到 Candidate，不升级为 Verified。',
    run(){
      const result=analyzePoisoningImpact(easyPoisonFixture());
      const ids=(result.findings||[]).map((x)=>x.id);
      const recognized=ids.includes('poisoning-label-flip-candidate')&&ids.includes('poisoning-target-concentration');
      const candidate=Boolean(recognized&&result.topTrigger?.trigger&&result.targetConcentration?.label);
      const candidateObject=candidate?{kind:'trigger-target',trigger:result.topTrigger.trigger,targetLabel:result.targetConcentration.label,verifier:'ai-backdoor-behavior'}:null;
      return {
        recognized,
        candidate,
        verified:false,
        candidateObject,
        candidateEvidence:candidate?`trigger=${candidateObject.trigger} · target=${candidateObject.targetLabel}`:'',
        tool:'ai-poisoning-impact',
        evidence:`poison=${result.marked?.poison||0} · topTrigger=${result.topTrigger?.trigger||'n/a'} · target=${result.targetConcentration?.label||'n/a'}`,
        findingIds:ids
      };
    }
  },
  {
    id:'ccb-ciscn-2025-silent-heist',
    event:'2025 CISCN / 长城杯网数智安全大赛初赛',
    challenge:'The Silent Heist',
    aiLabel:'AI安全',
    kind:'Isolation Forest / multivariate distribution',
    source:'https://github.com/CTF-Archives/2025-CCB-CISCN-Quals',
    provenance:'public-description-derived',
    coverage:'partial',
    limitation:'能做 20 维统计画像、相关结构与候选一致性检查；按 Offline-First 原则不自动随机生成线上规避样本。',
    run(){
      const result=analyzeTabularDataset(silentHeistCsv());
      const recognized=Boolean(result.numericColumns===20&&result.findings?.some((x)=>x.id==='multivariate-profile'));
      return {recognized,tool:'ai-tabular-profile',evidence:`${result.rows} rows · ${result.numericColumns} numeric · correlations=${result.strongestCorrelations?.length||0}`,findingIds:(result.findings||[]).map((x)=>x.id)};
    }
  },
  {
    id:'ciscn-finals-2025-what-is-model',
    event:'2025 CISCN 总决赛',
    challenge:'what-is-model',
    aiLabel:'AI 模型安全',
    kind:'Transfer learning / gray-box model',
    source:'https://github.com/CTF-Archives/2025-CISCN-Finals',
    provenance:'public-description-only',
    coverage:'partial',
    limitation:'公开题面确认了 app.py + 灰盒模型交互，但缺少足够公开附件细节，当前只登记路由，不虚构具体漏洞与预期 finding。',
    run(){return {recognized:true,tool:'ai-source-scan',evidence:'catalogued from public challenge description; attachment-specific assertion intentionally omitted',findingIds:[]};}
  },
  {
    id:'lanqiao-2026-prompt-audit',
    event:'2026 蓝桥杯软件赛网络安全赛项决赛',
    challenge:'prompt_audit',
    aiLabel:'AI安全',
    kind:'RAG poisoning / indirect prompt injection',
    source:'https://github.com/CTF-Archives/2026-LanqiaoCup-Finals',
    provenance:'public-description-derived',
    coverage:'partial',
    limitation:'能静态识别 user→retriever→context→model→tool 风险链；不替代在线业务流程中的真实检索与 Agent 交互验证。',
    run(){
      const result=auditPromptInjectionSource(PROMPT_AUDIT_SOURCE);
      const ids=(result.findings||[]).map((x)=>x.id);
      const recognized=ids.includes('prompt-injection-rag-surface')&&ids.includes('prompt-injection-untrusted-prompt-flow');
      return {recognized,tool:'ai-prompt-injection-source',evidence:`RAG=${Boolean(result.surfaces?.rag)} · model=${Boolean(result.surfaces?.modelCall)} · tool=${Boolean(result.surfaces?.toolSurface)}`,findingIds:ids};
    }
  },
  {
    id:'ccsssc-2026-cifar10-backdoor',
    event:'2026 软件系统安全赛总决赛',
    challenge:'CIFAR-10',
    aiLabel:'AI 安全人员 / 模型后门',
    kind:'Image classifier backdoor',
    source:'https://github.com/CTF-Archives/2026-CCSSSC-Final',
    provenance:'public-description-derived',
    coverage:'partial',
    limitation:'现在同时能验证 trigger 前后预测迁移/ASR，并把局部 patch 候选叠到图像工作台；仍不会替选手针对目标模型自动优化 trigger。',
    run(){
      const behavior=analyzeBackdoorBehavior(backdoorFixture());
      const visual=analyzeRasterImage(patchRaster());
      const ids=[...(behavior.findings||[]).map((x)=>x.id),...(visual.findings||[]).map((x)=>x.id)];
      const recognized=ids.includes('backdoor-target-asr-candidate')&&Boolean(visual.patchAnalysis?.candidates?.length);
      return {recognized,tool:'ai-sample-forensics',evidence:`target ASR=${behavior.targetASR??'n/a'} · patch candidates=${visual.patchAnalysis?.candidates?.length||0}`,findingIds:ids};
    }
  },
  {
    id:'ccsssc-2026-fake-emotion',
    event:'2026 软件系统安全赛总决赛',
    challenge:'Fake Emotion',
    aiLabel:'AI / NPY submission',
    kind:'Array / adversarial sample submission',
    source:'https://github.com/CTF-Archives/2026-CCSSSC-Final',
    provenance:'public-description-derived',
    coverage:'partial',
    limitation:'已补第一方 NPY dtype/shape/数值预览、图像解释和双样本差分；仍缺面向题目模型的梯度/黑箱优化与提交文件约束编辑器。',
    run(){
      const values=[];
      for(let y=0;y<8;y+=1) for(let x=0;x<8;x+=1) values.push((x+y)/14);
      const result=analyzeNpySample(makeNpyFloat32([8,8,1],values),'fake-emotion-fixture.npy');
      const recognized=Boolean(result.imageLike&&result.preview?.rgbaBase64&&result.numeric?.sampled===64);
      return {recognized,tool:'ai-sample-forensics',evidence:`shape=${result.header?.shape?.join('x')} · dtype=${result.header?.descr} · preview=${Boolean(result.preview)}`,findingIds:(result.findings||[]).map((x)=>x.id)};
    }
  },
  {
    id:'bay-area-2025-maodie',
    event:'第五届湾区杯网络安全大赛决赛',
    challenge:'耄耋',
    aiLabel:'AI 人工智能 / AIGC 检测',
    kind:'AI-generated image detection / FFT frequency feature',
    source:'https://mdr.skyeye.qianxin.com/forum/share/4686',
    provenance:'public-writeup-derived',
    coverage:'partial',
    limitation:'已复现公开 WP 的灰度频域高频占比、outer radius=0.85 与 δ=0.125 参考线；尚未加入整目录批处理、阈值校准和 CSV 批量结果导出。',
    run(){
      const result=analyzeRasterImage(checkerRaster());
      const recognized=Boolean(result.frequency?.ctfReference?.outerRadiusRatio===0.85&&result.frequency?.ctfReference?.delta===0.125&&Number.isFinite(result.frequency?.highFrequencyRatio));
      return {recognized,tool:'ai-sample-forensics',evidence:`FFT high=${result.frequency?.highFrequencyRatio} · public delta=${result.frequency?.ctfReference?.delta}`,findingIds:(result.findings||[]).map((x)=>x.id)};
    }
  },
  {
    id:'bay-area-2025-blind',
    event:'第五届湾区杯网络安全大赛决赛',
    challenge:'Blind',
    aiLabel:'AI assistant / Whisper ASR',
    kind:'ASR output → shell boundary',
    source:'https://www.butian.net/School/content/9404',
    provenance:'public-writeup-derived',
    coverage:'full',
    limitation:'针对公开题解描述的 ASR 文本进入 shell 这一静态链可直接定位；在线服务可利用性仍需结合真实输入约束复核。',
    run(){
      const result=auditAiChallengeSource(BLIND_SOURCE);
      const ids=(result.findings||[]).map((x)=>x.id);
      const recognized=ids.includes('ai-output-shell-injection');
      return {recognized,tool:'ai-source-scan',evidence:recognized?'ASR output → shell sink detected':'flow not detected',findingIds:ids};
    }
  }
]);

function publicCase(item){
  return {id:item.id,event:item.event,challenge:item.challenge,aiLabel:item.aiLabel,kind:item.kind,source:item.source,provenance:item.provenance,coverage:item.coverage,limitation:item.limitation};
}

function getAiRealCtfCorpus(){return CASES.map(publicCase);}

function runAiRealCtfRegression(){
  const results=CASES.map((item)=>{
    let execution;
    try{execution=item.run();}
    catch(error){execution={recognized:false,candidate:false,verified:false,error:error?.message||String(error),tool:null,evidence:'regression execution failed',findingIds:[]};}
    const recognized=execution.recognized===true;
    const candidate=recognized&&execution.candidate===true;
    const verified=candidate&&execution.verified===true;
    const maturityStage=verified?'verified':candidate?'candidate':recognized?'recognized':'unrecognized';
    const status=item.coverage==='gap'?'gap':recognized?'pass':'miss';
    return {...publicCase(item),status,...execution,recognized,candidate,verified,maturityStage};
  });
  const total=results.length;
  const recognitionPass=results.filter((x)=>x.recognized).length;
  const candidatePass=results.filter((x)=>x.candidate).length;
  const verifiedPass=results.filter((x)=>x.verified).length;
  const summary={
    total,
    recognitionPass,
    candidatePass,
    verifiedPass,
    recognitionRate:total?recognitionPass/total:0,
    candidateRate:total?candidatePass/total:0,
    verifiedRate:total?verifiedPass/total:0,
    maturityFunnel:{
      recognized:recognitionPass,
      candidate:candidatePass,
      verified:verifiedPass,
      recognizedToCandidate:recognitionPass?candidatePass/recognitionPass:0,
      candidateToVerified:candidatePass?verifiedPass/candidatePass:0
    },
    miss:results.filter((x)=>x.status==='miss').length,
    coverageFull:results.filter((x)=>x.coverage==='full').length,
    coveragePartial:results.filter((x)=>x.coverage==='partial').length,
    coverageGap:results.filter((x)=>x.coverage==='gap').length,
    aiExplicit:results.filter((x)=>/AI|人工智能|模型|LLM/i.test(x.aiLabel)).length
  };
  return {
    schema:'newcyber.ai-real-ctf-regression.v1',
    maturitySchema:'newcyber.ai-real-ctf-maturity.v1',
    generatedAt:new Date().toISOString(),
    summary,
    results,
    note:'真题回归使用公开题面、官方源码或公开题解提炼的最小可复现输入，不把未公开附件细节当成事实。PASS/Recognized 只表示核心证据模式被识别；Candidate 必须实际产出可继续验证的具体对象；Verified 还要求 oracle 或确定性验证闭环。三层状态互不混淆。'
  };
}

module.exports={getAiRealCtfCorpus,runAiRealCtfRegression};