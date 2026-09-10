'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {buildPromptAttackAutopilot}=require('../src/core/ai_prompt_attack_autopilot');
const {buildRemoteReplayPlan}=require('../src/core/ai_remote_replay_contract');

test('Batch55 prompt first wave spans categories and templates before repeating recipe variants',()=>{
  const promptPlan=buildPromptAttackAutopilot({
    context:'Agent uses MCP tools, RAG documents and conversation history while protecting hidden system prompt, token and flag',
    maxTemplates:12,
    maxProbes:256
  });
  const first=promptPlan.recommended.slice(0,12);
  assert.equal(promptPlan.recommendationPolicy.templateSelection,'category-round-robin');
  assert.equal(promptPlan.recommendationPolicy.probeSelection,'template-recipe-round-robin');
  assert.equal(new Set(first.map((x)=>x.templateId)).size,12);
  assert.ok(new Set(first.map((x)=>x.category)).size>=6,JSON.stringify(promptPlan.recommendationPolicy));
  assert.ok(first.every((x)=>x.recipeId==='baseline'));
});

test('Batch55 16-request replay budget is not monopolized by one prompt template',()=>{
  const promptPlan=buildPromptAttackAutopilot({
    context:'summarizer reads user controlled RAG documents and tools; recover hidden initial instruction and flag',
    maxTemplates:12,
    maxProbes:256
  });
  const autopilot={primaryDirection:'prompt-llm-security',directions:[{id:'prompt-llm-security'}],promptPlan};
  const closure={closed:false,primaryDirection:'prompt-llm-security',directions:[]};
  const replay=buildRemoteReplayPlan(autopilot,closure,{maxRemoteRequests:16,endpoint:'{{TARGET}}',flagFormat:'ctf{...}'});
  assert.equal(replay.contractCount,16);
  assert.ok(new Set(replay.contracts.map((x)=>x.templateId)).size>=12);
  assert.ok(new Set(replay.contracts.map((x)=>x.category)).size>=6);
  assert.equal(replay.executionPolicy.automatic,false);
  assert.equal(replay.executionPolicy.authorizationRequired,true);
});