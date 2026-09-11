'use strict';

const base=require('./finals_analyzer_batch86');
const {analyzeModelFingerprintCandidates}=require('./ai_model_fingerprint_ranker');
const {analyzeSubmissionBundle}=require('./challenge_submission_autopilot_v2');
const {buildChallengeSession}=require('./challenge_session_batch87');

function upsertCheck(analysis,check){analysis.autopilot||={};analysis.autopilot.automaticChecks||=[];const current=analysis.autopilot.automaticChecks.find((item)=>item.id===check.id);if(current)Object.assign(current,check);else analysis.autopilot.automaticChecks.push(check);}
function mergeFindings(analysis,findings){analysis.findings||=[];const seen=new Set(analysis.findings.map((item)=>`${item.id||item.title}:${item.file||''}:${item.evidence||''}`));for(const item of findings||[]){const key=`${item.id||item.title}:${item.file||''}:${item.evidence||''}`;if(seen.has(key))continue;seen.add(key);analysis.findings.push(item);}}
function looksFingerprintLog(file){
  const corpus=`${file?.path||''}\n${String(file?.text||'').slice(0,2*1024*1024)}`;
  const candidate=/(?:candidate[_ -]?model|model[_ -]?name|architecture|fingerprint|substitute|student)/i.test(corpus);
  const query=/(?:query[_ -]?id|sample[_ -]?id|\bquery\b|\binput\b|\bprompt\b)/i.test(corpus);
  const paired=/(?:victim[_ -]?(?:label|probs?|probabilities|logits)|oracle[_ -]?(?:label|probs?|probabilities)|teacher[_ -]?(?:label|probs?|logits)|reference[_ -]?(?:label|scores)|candidate[_ -]?(?:label|probs?|probabilities|logits)|student[_ -]?(?:label|probs?|logits)|fidelity|agreement)/i.test(corpus);
  return candidate&&query&&paired;
}
function statusRank(value){return{candidate:4,ambiguous:3,partial:2,gap:1}[value]||0;}
function chooseRun(runs){return runs.slice().sort((a,b)=>statusRank(b.result.status)-statusRank(a.result.status)||(b.result.bestCandidate?.agreement??-1)-(a.result.bestCandidate?.agreement??-1)||(b.result.bestCandidate?.queries??0)-(a.result.bestCandidate?.queries??0)||a.file.localeCompare(b.file))[0]||null;}

async function scanWorkspace(rootPath,options={}){
  const analysis=await base.scanWorkspace(rootPath,options);const files=await base.readCandidateFiles(rootPath,analysis);const runs=[];
  for(const file of files){if(!looksFingerprintLog(file))continue;try{const result=analyzeModelFingerprintCandidates(file.text);if(result.status!=='gap')runs.push({file:file.path,result});}catch{}}
  if(runs.length){
    const chosen=chooseRun(runs),result=chosen.result;
    analysis.aiModelFingerprintAutopilot={schema:'newcyber.ai-model-fingerprint-autopilot.v1',status:result.status,summary:{files:runs.length,candidates:result.candidates,eligible:result.eligible,rows:result.rows},file:chosen.file,bestCandidate:result.bestCandidate||null,result:result.result?{...result.result,source:`${result.result.source}:${chosen.file}`}:null,shortlist:result.shortlist,findings:result.findings.map((item)=>({...item,file:chosen.file})),next:result.next,notes:result.notes};
    mergeFindings(analysis,analysis.aiModelFingerprintAutopilot.findings);
    upsertCheck(analysis,{id:'ai-model-fingerprint-ranker',title:'Model Fingerprint / Extraction 候选排名',hits:result.status==='candidate'?1:0,detail:`status=${result.status}; candidates=${result.candidates}; eligible=${result.eligible}; file=${chosen.file}`});
  }else analysis.aiModelFingerprintAutopilot={schema:'newcyber.ai-model-fingerprint-autopilot.v1',status:'not-detected',summary:{files:0,candidates:0,eligible:0,rows:0},result:null,findings:[],next:null};

  analysis.challengeSession=buildChallengeSession(analysis);
  if(analysis.aiModelFingerprintAutopilot.status==='candidate'&&analysis.aiModelFingerprintAutopilot.result){
    const submission=analyzeSubmissionBundle(files,analysis);
    if(submission.status==='formatted'){
      analysis.submissionAutopilot=submission;mergeFindings(analysis,submission.findings);
      upsertCheck(analysis,{id:'challenge-submission-autopilot',title:'Submission 模板识别 / 自动封装',hits:1,detail:`${submission.result?.format||'unknown'} · ${submission.result?.template||'template'}`});
      analysis.challengeSession=buildChallengeSession(analysis);
    }
  }
  analysis.version=Math.max(Number(analysis.version)||1,87);return analysis;
}

function batch87Section(analysis){const auto=analysis.aiModelFingerprintAutopilot;if(!auto||auto.status==='not-detected')return'';const lines=['## Batch87 · Model Fingerprint / Extraction Ranker','',`- 状态：${auto.status} · file=${auto.file||'n/a'}`];if(auto.bestCandidate)lines.push(`- Top：${auto.bestCandidate.candidate} · agreement=${auto.bestCandidate.agreement==null?'n/a':Number(auto.bestCandidate.agreement).toFixed(4)} · queries=${auto.bestCandidate.queries} · cosine=${auto.bestCandidate.vectorCosine==null?'n/a':Number(auto.bestCandidate.vectorCosine).toFixed(4)}`);if(auto.next)lines.push(`- 下一步：${auto.next}`);lines.push('','> 只根据已有本地/授权 victim↔candidate transcript 做 fingerprint 排名；候选必须用独立 holdout 或题目 checker 确认，不会主动访问远程 victim。');return lines.join('\n');}
function buildMarkdownReport(analysis,notes=''){const report=base.buildMarkdownReport(analysis,notes);const section=batch87Section(analysis);return section?`${report.trim()}\n\n${section}\n`:report;}

module.exports={...base,scanWorkspace,buildMarkdownReport,batch87Section,looksFingerprintLog,chooseRun};
