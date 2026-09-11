'use strict';

const path=require('path');
const {getTrainingCurriculum}=require('./ai_training_curriculum');

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}
function normalize(value){return text(value).toLowerCase();}
function extension(value){const ext=path.extname(text(value)).toLowerCase();return ext||'';}

const SIGNALS=Object.freeze([
  {id:'prompt-injection',direction:'prompt-llm-security',weight:6,re:/prompt[- _]?injection|jailbreak|instruction override|提示词注入|越狱/i},
  {id:'system-prompt',direction:'prompt-llm-security',weight:5,re:/system[- _]?prompt|system instructions?|系统提示|内部指令/i},
  {id:'rag',direction:'prompt-llm-security',weight:5,re:/\brag\b|retriev(?:al|er|ed)|vectorstore|embedding search|检索增强|向量库/i},
  {id:'agent-tool',direction:'prompt-llm-security',weight:5,re:/agent|tool[_ -]?call|function[_ -]?call|mcp|dispatch_tool|工具调用|智能体/i},
  {id:'confused-deputy',direction:'prompt-llm-security',weight:6,re:/confused deputy|forward(?:ed|ing)? request|inter[- _]?agent|agent trust|代理转发|信任边界/i},
  {id:'adversarial',direction:'adversarial-example',weight:7,re:/adversarial|perturb|epsilon|\beps\b|fgsm|pgd|deepfool|linf|feature[_ -]?squeez|对抗样本|对抗检测|扰动/i},
  {id:'backdoor',direction:'backdoor-poisoning',weight:7,re:/backdoor|triggered_pred|target asr|attack success rate|后门|触发器/i},
  {id:'poisoning',direction:'backdoor-poisoning',weight:5,re:/poison(?:ing|ed)?|label flip|sample_loss|loss(?:es)?[_ -]?history|投毒|污染样本|loss 变化/i},
  {id:'model-extraction',direction:'model-extraction',weight:7,re:/model extraction|model stealing|substitute model|surrogate|query.*confidence|soft[- _]?label|模型抽取|模型窃取/i},
  {id:'oracle',direction:'model-extraction',weight:4,re:/oracle|confidence|probabilit(?:y|ies)|logits?|score vector|top[- _]?k|置信度|概率向量/i},
  {id:'inversion',direction:'privacy-leakage',weight:7,re:/model inversion|embedding inversion|reconstruct(?:ion|ed)?|hidden[- _]?state|reference.*reconstructed|模型反演|重建/i},
  {id:'privacy-leak',direction:'privacy-leakage',weight:5,re:/sensitive.*leak|secret.*leak|memor(?:isation|ization)|training data extraction|canary.*expos|敏感.*泄露|训练数据.*泄露/i},
  {id:'supply-chain',direction:'infra-supply-chain',weight:6,re:/torch\.load|weights_only|pickle|deserial|trust_remote_code|model artifact|safetensors|供应链|反序列化/i},
  {id:'dataset',direction:'dataset-pipeline-security',weight:4,re:/dataset|tabular|feature store|label|csv|dataframe|数据集|结构化特征/i},
  {id:'ocr',direction:'multimodal-ai',weight:5,re:/\bocr\b|bounding box|recognized_text|char_confidence|文字识别/i},
  {id:'audio',direction:'multimodal-ai',weight:5,re:/\baudio\b|\bwav\b|whisper|transcrib|speech|asr|语音|音频/i},
  {id:'deepfake',direction:'multimodal-ai',weight:6,re:/deepfake|xception|faceforensics|forged face|fake face|深伪|伪造人脸/i},
  {id:'onnx',direction:'adversarial-example',weight:3,re:/\bonnx\b|onnxruntime/i},
  {id:'verifier',direction:null,weight:3,re:/verifier|checker|判题|校验器/i},
  {id:'ssrf',direction:'prompt-llm-security',weight:3,re:/\bssrf\b|127\.0\.0\.1|localhost|internal service|内部服务/i}
]);

const EXTENSION_HINTS=Object.freeze({
  '.onnx':['onnx','adversarial'],'.npy':['adversarial','dataset'],'.npz':['dataset','backdoor'],
  '.pt':['supply-chain','backdoor'],'.pth':['supply-chain','backdoor'],'.pkl':['supply-chain','dataset'],'.pickle':['supply-chain','dataset'],
  '.safetensors':['supply-chain','inversion'],'.csv':['dataset'],'.tsv':['dataset'],'.jsonl':['dataset','model-extraction'],
  '.png':['ocr'],'.jpg':['ocr'],'.jpeg':['ocr'],'.bmp':['ocr'],'.wav':['audio'],'.mp3':['audio'],'.flac':['audio'],
  '.mp4':['deepfake'],'.avi':['deepfake'],'.mov':['deepfake'],'.pcap':['dataset'],'.pcapng':['dataset']
});

function analysisText(analysis={}){
  const chunks=[];
  for(const file of list(analysis.files)){
    chunks.push(file.path,file.type,file.format,file.language);
    for(const finding of list(file.findings))chunks.push(finding.id,finding.title,finding.meaning,finding.evidence);
  }
  for(const finding of list(analysis.findings))chunks.push(finding.id,finding.title,finding.meaning,finding.evidence,finding.file);
  for(const check of list(analysis.autopilot?.automaticChecks))chunks.push(check.id,check.title,check.detail);
  for(const key of ['aiPreprocessingManifest','aiContestAutopilot','onnxContestAutopilot','archiveIngest','recoveredArtifacts','candidates']){
    if(analysis[key]!=null){try{chunks.push(JSON.stringify(analysis[key]).slice(0,120000));}catch{}}
  }
  return chunks.map(text).filter(Boolean).join('\n').slice(0,500000);
}

function detectSignals(analysis={}){
  const haystack=analysisText(analysis);
  const found=[];
  for(const signal of SIGNALS){
    if(signal.re.test(haystack))found.push({id:signal.id,direction:signal.direction,weight:signal.weight,source:'analysis-text'});
  }
  const extCounts={};
  for(const file of list(analysis.files)){
    const ext=extension(file.path||file.name);if(!ext)continue;extCounts[ext]=(extCounts[ext]||0)+1;
  }
  for(const [ext,count] of Object.entries(extCounts)){
    for(const id of EXTENSION_HINTS[ext]||[]){
      const base=SIGNALS.find((x)=>x.id===id);
      found.push({id,direction:base?.direction||null,weight:Math.min(4,1+Math.log2(count+1)),source:`extension:${ext}`,count});
    }
  }
  const merged=new Map();
  for(const item of found){
    const prev=merged.get(item.id);
    if(!prev){merged.set(item.id,{...item,sources:[item.source]});continue;}
    prev.weight=Math.max(prev.weight,item.weight);
    if(item.source&&!prev.sources.includes(item.source))prev.sources.push(item.source);
    prev.count=Math.max(Number(prev.count)||0,Number(item.count)||0)||undefined;
  }
  return [...merged.values()].sort((a,b)=>b.weight-a.weight||a.id.localeCompare(b.id));
}

function words(value){
  return new Set(normalize(value).split(/[^a-z0-9\u4e00-\u9fff]+/).filter((x)=>x.length>=3&&!['training','challenge','public','synthetic','security','candidate','model','ctf'].includes(x)));
}
function overlapScore(a,b){
  const left=words(a),right=words(b);let hit=0;
  for(const token of left)if(right.has(token))hit+=Math.min(2,0.6+token.length/12);
  return hit;
}
function rowText(row){return [row.direction,row.family,row.challenge,row.event,row.capability,row.provenance?.title,row.provenance?.label].map(text).join(' ');}

function matchTrainingFamilies(analysis={},options={}){
  const curriculum=options.curriculum||getTrainingCurriculum();
  const signals=detectSignals(analysis);
  const directions=new Map();
  for(const signal of signals){if(!signal.direction)continue;directions.set(signal.direction,(directions.get(signal.direction)||0)+signal.weight);}
  const signalText=signals.map((x)=>x.id.replace(/-/g,' ')).join(' ');
  const matches=[];
  for(const row of list(curriculum.cases)){
    let score=0;const reasons=[];
    const directionWeight=directions.get(row.direction)||0;
    if(directionWeight){const add=Math.min(12,directionWeight);score+=add;reasons.push(`direction:${row.direction}+${add.toFixed(1)}`);}
    const lexical=overlapScore(signalText,rowText(row));
    if(lexical>0){score+=lexical;reasons.push(`family-overlap+${lexical.toFixed(1)}`);}
    for(const signal of signals){
      const key=signal.id.replace(/-/g,' ');const hay=normalize(rowText(row));
      if(hay.includes(key)||key.split(' ').every((part)=>part.length<3||hay.includes(part))){
        const add=Math.min(5,signal.weight*0.55);score+=add;reasons.push(`${signal.id}+${add.toFixed(1)}`);
      }
    }
    if(score<=0)continue;
    matches.push({id:row.id,event:row.event,challenge:row.challenge,direction:row.direction,family:row.family,caseType:row.caseType,score:Number(score.toFixed(3)),reasons:[...new Set(reasons)].slice(0,8),capability:row.capability||null,provenance:row.provenance||null});
  }
  matches.sort((a,b)=>b.score-a.score||a.id.localeCompare(b.id));
  const limit=Math.max(1,Math.min(30,Number(options.limit)||10));
  const top=matches.slice(0,limit);
  const best=top[0]?.score||0;
  const status=best>=12?'strong':best>=7?'medium':best>=3?'weak':'not-detected';
  const directionRanking=[...directions.entries()].map(([direction,score])=>({direction,score:Number(score.toFixed(3))})).sort((a,b)=>b.score-a.score||a.direction.localeCompare(b.direction));
  return {
    schema:'newcyber.ai-training-family-match.v1',status,
    signals,directionRanking,matches:top,
    summary:{curriculumCases:Number(curriculum.summary?.cases)||list(curriculum.cases).length,matchedCases:matches.length,returned:top.length,bestScore:best},
    next:status==='not-detected'?'没有足够证据映射到已训练赛题家族；继续依赖通用分析器。':`优先复用 ${top.slice(0,3).map((x)=>`${x.event}/${x.challenge}`).join('；')} 的分析策略，并以当前附件证据重新验证，不直接套用历史答案。`,
    notes:['匹配只用于选择分析策略，不会把历史赛题答案、Flag 或 exploit payload 迁移到当前题目。','得分来自当前附件证据、finding 文本、文件类型和 curriculum metadata；不会仅凭题名判定题型。']
  };
}

module.exports={SIGNALS,EXTENSION_HINTS,analysisText,detectSignals,overlapScore,matchTrainingFamilies};
