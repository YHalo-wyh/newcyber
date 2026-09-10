'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {buildPromptAttackAutopilot,PROBE_RECIPES}=require('../src/core/ai_prompt_attack_autopilot');
const {DIRECTIONS,buildFiveDirectionAutopilot}=require('../src/core/ai_five_direction_competition_autopilot');
const batch54=require('../src/core/finals_analyzer_batch54');

const root=path.join(__dirname,'..');
const read=(file)=>fs.readFileSync(path.join(root,file),'utf8');

test('Batch54 prompt autopilot removes mode split and expands the full library into 200+ concrete probes',()=>{
  const plan=buildPromptAttackAutopilot({context:'LLM challenge: recover hidden system prompt and flag from a chat endpoint'});
  assert.equal(plan.mode,'competition-native');
  assert.ok(plan.templateCount>=25,`templates=${plan.templateCount}`);
  assert.equal(plan.recipeCount,PROBE_RECIPES.length);
  assert.ok(plan.recipeCount>=8);
  assert.ok(plan.probeCount>=200,`probes=${plan.probeCount}`);
  assert.ok(plan.recommended.length>=20);
  assert.ok(plan.coverage.includes('direct'));
  assert.ok(plan.coverage.includes('indirect'));
  assert.ok(plan.coverage.includes('rag'));
  assert.ok(plan.coverage.includes('agent-tool'));
  assert.ok(plan.coverage.includes('secret-boundary'));
  assert.ok(plan.coverage.includes('multi-turn'));
  assert.equal(plan.executionPolicy.networkExecution,false);
  assert.equal(plan.executionPolicy.automaticRemoteAttack,false);
});

test('Batch54 prompt ranking adapts to summarizer/secret and agent/tool challenge context',()=>{
  const summarizer=buildPromptAttackAutopilot({context:'AI summarizer filters the flag and hidden initial instruction; document content is user controlled'});
  const topSummary=new Set(summarizer.rankedTemplates.slice(0,10).map((x)=>x.category));
  assert.ok(topSummary.has('secret-boundary'));
  assert.ok(topSummary.has('indirect'));
  assert.ok(summarizer.probePool.some((x)=>x.recipeId==='encoding-fallback'));

  const agent=buildPromptAttackAutopilot({context:'Agent reads MCP tool output and may call function tools without confirmation'});
  assert.equal(agent.rankedTemplates[0].category,'agent-tool');
  assert.ok(agent.remoteAnswerTemplates.some((x)=>x.id==='agent-tool-output'));
});

test('Batch54 fixes exactly the five official stage-one directions as the default competition workflow',()=>{
  assert.deepEqual(DIRECTIONS.map((x)=>x.id),[
    'prompt-llm-security','adversarial-example','privacy-leakage','backdoor-poisoning','infra-supply-chain'
  ]);
  assert.deepEqual(DIRECTIONS.map((x)=>x.title),[
    '提示词工程与大模型安全','对抗样本攻击','模型隐私与数据泄露','模型后门与数据投毒','AI 基础设施与供应链安全'
  ]);
});

test('Batch54 five-direction autopilot ranks evidence but never disables the other four directions',()=>{
  const analysis={
    files:[{path:'rag_agent.py',extension:'.py',type:'PYTHON',metadata:{summary:'retriever similarity_search tool_calls system prompt'}}],
    findings:[{id:'prompt-injection-rag-surface',title:'RAG surface'}],
    candidates:{flags:[]}
  };
  const plan=buildFiveDirectionAutopilot(analysis,{endpoint:'{{TARGET}}',flagFormat:'ctf{...}'});
  assert.equal(plan.mode,'competition-native');
  assert.equal(plan.goal,'flag-closure');
  assert.equal(plan.directions.length,5);
  assert.equal(new Set(plan.directions.map((x)=>x.id)).size,5);
  assert.equal(plan.primaryDirection,'prompt-llm-security');
  assert.ok(plan.promptPlan.probeCount>=200);
  assert.equal(plan.policy.remoteTargetExecution,'suggest-only');
  assert.equal(plan.policy.arbitraryNetworkAttack,false);
  assert.ok(plan.directions.every((x)=>x.remoteTemplates.length>=2));
});

test('Batch54 remote target output is a suggested answer/request contract rather than hidden execution',()=>{
  const plan=buildFiveDirectionAutopilot({files:[{path:'model.onnx',extension:'.onnx',type:'ONNX',metadata:{}}],findings:[],candidates:{flags:[]}},{});
  const supply=plan.directions.find((x)=>x.id==='infra-supply-chain');
  assert.ok(supply.remoteTemplates.some((x)=>/建议答案|验证请求/.test(x.title)));
  assert.ok(supply.remoteTemplates.every((x)=>typeof x.template==='string'&&x.template.length>20));
  assert.equal(plan.policy.localDeterministicAnalysis,'automatic');
  assert.equal(plan.policy.remoteTargetExecution,'suggest-only');
});

test('Batch54 workspace attachment exposes five-direction plan to Challenge Session and report',()=>{
  const analysis={challengeSession:{solverLedger:[],aiHandoff:{}},candidates:{flags:[]}};
  const plan=buildFiveDirectionAutopilot({files:[{path:'poison_dataset.csv',extension:'.csv',metadata:{trigger:'patch',asr:0.9}}],findings:[],candidates:{flags:[]}});
  batch54.attachCompetitionAutopilot(analysis,plan);
  assert.equal(analysis.aiCompetitionAutopilot,plan);
  assert.equal(analysis.challengeSession.aiCompetitionAutopilot,plan);
  assert.ok(analysis.challengeSession.solverLedger.some((x)=>x.id==='ai-five-direction-autopilot'));
  assert.equal(analysis.challengeSession.aiHandoff.competitionNative.primaryDirection,plan.primaryDirection);
  const section=batch54.buildCompetitionAutopilotSection(analysis);
  assert.match(section,/AI Five-Direction Competition Autopilot/);
  assert.match(section,/Remote Target Suggested Answer Templates/);
});

test('Batch54 UI is competition-native, de-carded, and loaded after Batch53',()=>{
  const promptUi=read('renderer/ai_prompt_injection_tools.js');
  const sessionUi=read('renderer/challenge_session_batch54.js');
  const css=read('renderer/styles/challenge_session_batch54.css');
  const html=read('renderer/toolbox.html');
  assert.doesNotThrow(()=>new vm.Script(promptUi,{filename:'ai_prompt_injection_tools.js'}));
  assert.doesNotThrow(()=>new vm.Script(sessionUi,{filename:'challenge_session_batch54.js'}));
  assert.doesNotMatch(promptUi,/competitionOnly|赛题高频/);
  assert.match(promptUi,/比赛原生/);
  assert.match(sessionUi,/AI FIVE-DIRECTION AUTOPILOT/);
  assert.match(sessionUi,/COMPETITION-NATIVE \/ FLAG-CLOSURE/);
  assert.match(sessionUi,/建议执行 \/ 不自动发包/);
  assert.ok(html.indexOf('challenge_session_batch54.js')>html.indexOf('challenge_session_batch53.js'));
  assert.ok(html.includes('styles/challenge_session_batch54.css'));
  assert.doesNotMatch(sessionUi,/fetch\s*\(|XMLHttpRequest|https?:\/\//i);
  assert.doesNotMatch(css,/grid-template-columns:\s*repeat\(/i);
});

test('Batch54 compatibility entry points production workspace scans to newest wrapper while preserving Batch53 marker',()=>{
  const entry=read('src/core/finals_analyzer_batch15.js');
  assert.match(entry,/finals_analyzer_batch53/);
  assert.match(entry,/require\('\.\/finals_analyzer_batch54'\)/);
});
