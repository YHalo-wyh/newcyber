'use strict';

const DIRECTIONS=Object.freeze([
  {
    id:'prompt-llm-security',
    title:'提示词工程与大模型安全',
    tools:['ai-skill-matrix','ai-prompt-injection-suite','ai-prompt-injection-source','ai-prompt-injection-evaluate','ai-source-scan'],
    hint:'补模型/Agent 响应、toolCalls、RAG/工具输出或应用源码；优先验证系统提示泄露、间接注入与越权工具调用。',
    pathHint:/(?:prompt|system[_ -]?prompt|rag|retriev|agent|tool[_ -]?call|llm)/i,
    findingHint:/(?:prompt|jailbreak|system prompt|rag|tool call|tool[_ -]?call|llm|越狱|提示词|间接注入|系统提示|工具调用)/i
  },
  {
    id:'adversarial-example',
    title:'对抗样本攻击',
    tools:['ai-skill-matrix','ai-adversarial-audit','ai-adversarial-batch','ai-adversarial-harness','ai-npy-sample-compare','ai-image-raster-compare'],
    hint:'补 original/adversarial、epsilon、norm、clip 与模型预测；以官方 preprocessing/verifier 复算预算和攻击成功率。',
    pathHint:/(?:adversarial|adv[_-]|x_adv|epsilon|pgd|fgsm|cw[_-]?attack)/i,
    findingHint:/(?:adversarial|epsilon|perturb|norm budget|对抗样本|扰动|预算)/i
  },
  {
    id:'privacy-leakage',
    title:'模型隐私与数据泄露',
    tools:['ai-skill-matrix','ai-privacy-audit','ai-privacy-harness','ai-model-extraction','ai-model-extraction-harness','ai-model-inversion','ai-ocr-extraction'],
    hint:'补 member/non-member 统计、模型 query transcript、embedding/gradient 或 reference/reconstruction；保留 AUC、TPR@FPR、holdout fidelity 等竞争指标。',
    pathHint:/(?:membership|privacy|extract|steal|inversion|reconstruct|embedding|gradient|ocr)/i,
    findingHint:/(?:membership|privacy|extract|inversion|reconstruct|fidelity|隐私|泄露|模型窃取|模型逆向|重建)/i
  },
  {
    id:'backdoor-poisoning',
    title:'模型后门与数据投毒',
    tools:['ai-skill-matrix','ai-dataset-security','ai-dataset-harness','ai-poisoning-impact','ai-backdoor-behavior'],
    hint:'补 clean/poison 标记、trigger、original/target label 与 clean/trigger/control 三组预测；优先验证 trigger 与目标标签的因果关系。',
    pathHint:/(?:poison|backdoor|trigger|trojan|clean[_-]?label|target[_-]?label)/i,
    findingHint:/(?:poison|backdoor|trigger|trojan|投毒|后门|触发器)/i
  },
  {
    id:'infra-supply-chain',
    title:'AI 基础设施与供应链安全',
    tools:['ai-skill-matrix','ai-supply-chain','ai-model-scan','ai-source-scan'],
    hint:'补模型加载/下载源码、requirements/pyproject、模型工件与 provenance；重点核对 unsafe load、remote code、revision、依赖源和归档边界。',
    pathHint:/(?:requirements|pyproject|checkpoint|model|safetensors|\.pt$|\.pth$|\.pkl$|\.pickle$|\.joblib$|huggingface|transformers)/i,
    findingHint:/(?:supply|unsafe|pickle|torch\.load|trust_remote_code|dependency|revision|provenance|供应链|反序列化|远程代码)/i
  }
]);

const STATUS_RANK=Object.freeze({'data-needed':0,'no-explicit-finding':1,candidate:2,evidence:3});
const NEXT_RANK=Object.freeze({candidate:40,'data-needed':30,'no-explicit-finding':20,evidence:10});

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'').trim();}
function severityRank(value){return ({high:3,medium:2,low:1,info:1}[text(value).toLowerCase()]||0);}
function compactEvidence(value,max=220){const s=text(value).replace(/\s+/g,' ');return s.length>max?`${s.slice(0,max-1)}…`:s;}

function matrixSkills(file){
  const matrix=file?.metadata?.aiSkillMatrix;
  return list(matrix?.skills||matrix?.directions);
}

function metadataForDirection(file,direction){
  const m=file?.metadata||{};
  if(direction.id==='prompt-llm-security')return [m.aiPromptInjection,m.promptInjectionAudit,m.aiAudit].filter(Boolean);
  if(direction.id==='adversarial-example')return [m.aiAdversarial,m.adversarialAudit,m.aiSampleForensics,m.npyComparison,m.rasterComparison].filter(Boolean);
  if(direction.id==='privacy-leakage')return [m.aiPrivacy,m.privacyAudit,m.modelExtractionAudit,m.aiModelExtraction,m.modelInversionAudit,m.aiModelInversion,m.ocrExtractionAudit].filter(Boolean);
  if(direction.id==='backdoor-poisoning')return [m.aiDatasetSecurity,m.datasetSecurity,m.poisoningImpact,m.aiPoisoningImpact,m.backdoorBehavior,m.aiBackdoorBehavior].filter(Boolean);
  if(direction.id==='infra-supply-chain')return [m.aiSupplyChain,m.modelAudit,m.model].filter(Boolean);
  return [];
}

function objectSignals(value){
  if(!value||typeof value!=='object')return {findings:[],explicitEvidence:false,explicitClean:false};
  const findings=list(value.findings);
  const verdict=text(value.verdict||value.status||value.result||value.exposure).toLowerCase();
  const explicitEvidence=Boolean(
    findings.some((x)=>severityRank(x?.severity)>=2)||
    /(?:evidence|vulnerable|candidate-failure|within-budget-success|exposed|high-risk|affected|backdoor|poison)/.test(verdict)||
    value.withinBudget===true&&Boolean(value.outcome?.success||value.attackSuccess||value.success)||
    Number(value.fidelity)>=0.8||Number(value.holdoutFidelity)>=0.8||
    Number(value.competitionMetrics?.auc)>=0.7||Number(value.competitionMetrics?.tprAtFpr10)>=0.25||
    list(value.triggerCandidates).length>0||list(value.conflictingLabels).length>0
  );
  const explicitClean=Boolean(
    verdict&&/(?:no-explicit-finding|clean|limited|not-affected|pass|safe)/.test(verdict)&&!explicitEvidence||
    ('findings' in value&&findings.length===0&&!explicitEvidence)
  );
  return {findings,explicitEvidence,explicitClean};
}

function evidenceFromFinding(file,direction){
  const out=[];
  for(const finding of list(file?.findings)){
    const hay=`${finding?.id||''} ${finding?.originalId||''} ${finding?.title||''} ${finding?.evidence||''}`;
    if(!direction.findingHint.test(hay))continue;
    out.push({
      file:file.path||file.name||'workspace',
      kind:'finding',
      severity:finding.severity||'info',
      title:finding.title||finding.originalId||finding.id||'AI 安全线索',
      evidence:compactEvidence(finding.evidence||finding.id||finding.title)
    });
  }
  return out;
}

function mergeMatrixState(file,direction,state){
  const skill=matrixSkills(file).find((x)=>x?.id===direction.id||x?.skill===direction.id);
  if(!skill)return;
  const status=text(skill.status)||'data-needed';
  if((STATUS_RANK[status]??0)>(STATUS_RANK[state.status]??0))state.status=status;
  if(skill.confidence)state.confidence=skill.confidence;
  for(const finding of list(skill.findings).slice(0,8))state.evidence.push({
    file:file.path||file.name||'workspace',kind:'skill-matrix',severity:finding.severity||'info',title:finding.title||finding.id||direction.title,evidence:compactEvidence(finding.evidence||finding.meaning||finding.id)
  });
  if(skill.nextAction)state.matrixNextAction=skill.nextAction;
}

function analyzeDirection(analysis,direction){
  const state={...direction,status:'data-needed',confidence:'none',files:[],evidence:[],signals:{structured:0,findings:0,pathHints:0,matrix:0},matrixNextAction:null};
  let sawStructured=false,sawExplicitClean=false,sawCandidate=false,sawEvidence=false;
  for(const file of list(analysis?.files)){
    const path=text(file.path||file.name);
    const before=state.status;
    mergeMatrixState(file,direction,state);
    if(state.status!==before){state.signals.matrix++;sawStructured=true;if(state.status==='evidence')sawEvidence=true;else if(state.status==='candidate')sawCandidate=true;else if(state.status==='no-explicit-finding')sawExplicitClean=true;}

    const metas=metadataForDirection(file,direction);
    if(metas.length){
      sawStructured=true;state.signals.structured+=metas.length;
      for(const meta of metas){
        const sig=objectSignals(meta);
        if(sig.explicitEvidence)sawEvidence=true;
        else if(sig.explicitClean)sawExplicitClean=true;
        else sawCandidate=true;
        for(const finding of sig.findings.slice(0,8))state.evidence.push({file:path||'workspace',kind:'metadata',severity:finding.severity||'info',title:finding.title||finding.id||direction.title,evidence:compactEvidence(finding.evidence||finding.meaning||finding.id)});
        if(!sig.findings.length&&sig.explicitEvidence)state.evidence.push({file:path||'workspace',kind:'metadata',severity:'medium',title:`${direction.title} 结构化结果`,evidence:compactEvidence(meta.verdict||meta.status||meta.result||'结构化分析器给出显式证据信号')});
      }
    }

    const findingEvidence=evidenceFromFinding(file,direction);
    if(findingEvidence.length){
      state.evidence.push(...findingEvidence);state.signals.findings+=findingEvidence.length;
      if(findingEvidence.some((x)=>severityRank(x.severity)>=2))sawEvidence=true;else sawCandidate=true;
    }

    if(direction.pathHint.test(path)){
      state.signals.pathHints++;sawCandidate=true;
      if(!state.evidence.some((x)=>x.file===path))state.evidence.push({file:path||'workspace',kind:'path-hint',severity:'info',title:'文件名/路径命中方向关键词',evidence:path});
    }

    if(metas.length||findingEvidence.length||direction.pathHint.test(path)||matrixSkills(file).some((x)=>x?.id===direction.id||x?.skill===direction.id))state.files.push(path||'workspace');
  }

  if((STATUS_RANK[state.status]??0)<3){
    if(sawEvidence)state.status='evidence';
    else if(sawCandidate)state.status='candidate';
    else if(sawStructured&&sawExplicitClean)state.status='no-explicit-finding';
    else state.status='data-needed';
  }
  if(state.confidence==='none')state.confidence=state.status==='evidence'?'high':state.status==='candidate'?'medium':state.status==='no-explicit-finding'?'low':'none';
  state.files=[...new Set(state.files)].slice(0,16);
  state.evidence=state.evidence.filter((item,index,arr)=>arr.findIndex((x)=>`${x.file}|${x.title}|${x.evidence}`===`${item.file}|${item.title}|${item.evidence}`)===index).slice(0,18);
  state.nextAction=state.matrixNextAction||direction.hint;
  delete state.pathHint;delete state.findingHint;delete state.matrixNextAction;
  return state;
}

function isAiWorkspace(analysis){
  if(list(analysis?.categories).some((x)=>/(?:人工智能|AI\s*\/\s*ML|\bAI\b)/i.test(text(x?.name))&&Number(x?.score)>0))return true;
  return list(analysis?.files).some((file)=>{
    const m=file?.metadata||{},p=text(file?.path);
    return Boolean(m.aiAudit||m.aiTabular||m.aiSupplyChain||m.aiDatasetSecurity||m.aiSkillMatrix||m.model||m.modelAudit||m.ocrExtractionAudit||m.modelExtractionAudit||m.modelInversionAudit)||/\.(?:pt|pth|pkl|pickle|joblib|safetensors|npy|npz|onnx|gguf|csv|tsv)$/i.test(p);
  });
}

function buildAiStage1Mission(analysis={}){
  const applicable=isAiWorkspace(analysis);
  const directions=DIRECTIONS.map((direction)=>analyzeDirection(analysis,direction));
  const counts={evidence:0,candidate:0,'no-explicit-finding':0,'data-needed':0};
  for(const item of directions)counts[item.status]=(counts[item.status]||0)+1;
  const detectedFiles=new Set(directions.flatMap((x)=>x.files)).size;
  const queue=directions
    .map((item)=>({...item,nextPriority:NEXT_RANK[item.status]??0}))
    .filter((item)=>item.status!=='evidence'||directions.every((x)=>x.status==='evidence'))
    .sort((a,b)=>b.nextPriority-a.nextPriority||b.evidence.length-a.evidence.length||a.title.localeCompare(b.title))
    .map(({nextPriority,...item})=>item);
  const next=queue[0]||directions[0];
  return {
    schema:'newcyber.ai-stage1-mission.v1',
    applicable,
    generatedAt:new Date().toISOString(),
    officialCoverage:directions.length,
    directions,
    queue,
    nextDirection:next?{id:next.id,title:next.title,status:next.status,confidence:next.confidence,nextAction:next.nextAction,tools:next.tools,files:next.files.slice(0,6)}:null,
    summary:{...counts,detectedFiles,covered:directions.filter((x)=>x.status!=='data-needed').length,attentionNeeded:counts.candidate+counts['data-needed'],evidenceItems:directions.reduce((sum,x)=>sum+x.evidence.length,0)},
    notes:[
      'Mission 聚合的是 Workspace 已有结构化结果与可追溯 finding；文件名/路径关键词最多只能把方向提升为 candidate，不会单独形成 evidence。',
      '该层只做离线证据编排，不执行题目程序、不连接远程目标、不自动提交答案。'
    ]
  };
}

function attachAiStage1Mission(analysis={}){
  const mission=buildAiStage1Mission(analysis);
  analysis.aiStage1Mission=mission;
  if(analysis.challengeSession)analysis.challengeSession.aiStage1Mission=mission;
  const autopilot=analysis.autopilot;
  if(!autopilot)return mission;
  autopilot.aiStage1Mission=mission;
  if(!mission.applicable)return mission;

  const checks=list(autopilot.automaticChecks);
  if(!checks.some((x)=>x.id==='ai-stage1-mission'))checks.push({id:'ai-stage1-mission',title:'AI 五方向 Stage-One Mission',hits:Math.max(1,mission.summary.detectedFiles)});
  autopilot.automaticChecks=checks;
  autopilot.summary={...(autopilot.summary||{}),automaticCheckKinds:checks.length,automaticCheckHits:checks.reduce((sum,x)=>sum+(Number(x.hits)||0),0),aiStage1Covered:mission.summary.covered,aiStage1Evidence:mission.summary.evidence};

  const next=mission.nextDirection;
  if(next){
    const action={id:'ai-stage1-mission',priority:75,level:next.status==='candidate'?'hot':'normal',title:`AI 五方向下一步：${next.title}`,detail:`${next.status} · ${next.nextAction}`,tool:next.tools?.[0]||'ai-skill-matrix'};
    const actions=list(autopilot.actions).filter((x)=>x.id!=='ai-stage1-mission');
    actions.push(action);
    autopilot.actions=actions.sort((a,b)=>(Number(b.priority)||0)-(Number(a.priority)||0)).slice(0,4);
  }
  return mission;
}

module.exports={DIRECTIONS,isAiWorkspace,buildAiStage1Mission,attachAiStage1Mission};
