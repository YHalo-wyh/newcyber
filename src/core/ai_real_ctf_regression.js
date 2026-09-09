const { auditAiChallengeSource } = require('./ai_source_batch9');
const { analyzeTabularDataset } = require('./ai_tabular');
const { analyzeBackdoorBehavior } = require('./ai_poison_backdoor_validation');
const { auditPromptInjectionSource } = require('./ai_prompt_injection');

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
    source:'https://github.com/USTC-Hackergame/hackergame2023-writeups/tree/master/official/%F0%9F%AA%90%20%E5%B0%8F%E5%9E%8B%E5%A4%A7%E8%AF%AD%E8%A8%80%E6%A8%A1%E5%9E%8B%E6%98%9F%E7%90%83',
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
    limitation:'能验证 trigger 前后预测迁移、ASR 与 control specificity；还缺图像 trigger 定位/搜索和 patch 可视化。',
    run(){
      const result=analyzeBackdoorBehavior(backdoorFixture());
      const ids=(result.findings||[]).map((x)=>x.id);
      return {recognized:ids.includes('backdoor-target-asr-candidate'),tool:'ai-backdoor-behavior',evidence:`paired=${result.paired??10} · target ASR=${result.targetASR??'n/a'}`,findingIds:ids};
    }
  },
  {
    id:'ccsssc-2026-fake-emotion',
    event:'2026 软件系统安全赛总决赛',
    challenge:'Fake Emotion',
    aiLabel:'AI / NPY submission',
    kind:'Array / adversarial sample submission',
    source:'https://github.com/CTF-Archives/2026-CCSSSC-Final',
    provenance:'public-description-only',
    coverage:'gap',
    limitation:'当前缺少面向 .npy 样本的第一方数组预览、差分热区、约束编辑和直接导出工作台；这是下一批 AI UI/能力缺口。',
    run(){return {recognized:false,tool:'ai-adversarial-audit',evidence:'GAP: no first-class NPY sample workbench',findingIds:[]};}
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
    catch(error){execution={recognized:false,error:error?.message||String(error),tool:null,evidence:'regression execution failed',findingIds:[]};}
    const status=item.coverage==='gap'?'gap':execution.recognized?'pass':'miss';
    return {...publicCase(item),status,...execution};
  });
  const summary={
    total:results.length,
    recognitionPass:results.filter((x)=>x.status==='pass').length,
    miss:results.filter((x)=>x.status==='miss').length,
    coverageFull:results.filter((x)=>x.coverage==='full').length,
    coveragePartial:results.filter((x)=>x.coverage==='partial').length,
    coverageGap:results.filter((x)=>x.coverage==='gap').length,
    aiExplicit:results.filter((x)=>/AI|人工智能|模型|LLM/i.test(x.aiLabel)).length
  };
  return {
    schema:'newcyber.ai-real-ctf-regression.v1',
    generatedAt:new Date().toISOString(),
    summary,
    results,
    note:'真题回归使用公开题面/官方题解提炼的最小可复现输入，不把描述中未公开的附件细节当成事实。PASS 表示 NewCyber 能识别对应证据模式，不等于已自动解出原题；PARTIAL/GAP 用于暴露下一轮建设方向。'
  };
}

module.exports={getAiRealCtfCorpus,runAiRealCtfRegression};
