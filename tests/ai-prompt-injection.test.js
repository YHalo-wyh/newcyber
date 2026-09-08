const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const {
  buildPromptInjectionSuite,
  evaluatePromptInjectionRun,
  auditPromptInjectionSource,
  DEFAULT_MARKER,
  DEFAULT_CANARY,
  DEFAULT_TOOL
}=require('../src/core/ai_prompt_injection');
const { runTool }=require('../src/core/tool_router');

test('prompt injection suite covers direct, indirect, RAG, tool, secret and multi-turn cases',()=>{
  const result=buildPromptInjectionSuite({});
  assert.ok(result.templates.length>=25);
  const categories=new Set(result.templates.map((x)=>x.category));
  for (const category of ['direct','indirect','rag','agent-tool','secret-boundary','multi-turn']) assert.ok(categories.has(category));
  assert.ok(result.templates.some((x)=>x.id==='direct-instruction-override' && x.payload.includes(DEFAULT_MARKER)));
  assert.ok(result.templates.some((x)=>x.id==='canary-exfiltration' && x.payload.includes(DEFAULT_CANARY)));
  assert.ok(result.templates.some((x)=>x.id==='tool-output-injection' && x.payload.includes(DEFAULT_TOOL)));
  assert.equal(new Set(result.templates.map((x)=>x.id)).size,result.templates.length);
});

test('prompt injection suite exposes a competition-only pack with common CTF payload families',()=>{
  const result=buildPromptInjectionSuite({competitionOnly:true});
  assert.ok(result.templates.length>=20);
  assert.equal(result.competitionCount,result.templates.length);
  assert.ok(result.templates.every((x)=>x.competition===true));
  for (const id of [
    'developer-role-spoof',
    'assistant-prefix-completion',
    'output-format-hijack',
    'markdown-fence-breakout',
    'rag-authority-spoof',
    'tool-confirmation-bypass',
    'repeat-hidden-context',
    'multi-turn-trigger-word'
  ]) assert.ok(result.templates.some((x)=>x.id===id),id);
});

test('prompt injection suite supports category filtering and custom harmless markers',()=>{
  const result=buildPromptInjectionSuite({category:'rag',marker:'SAFE_MARKER_X',canary:'SAFE_CANARY_X',tool:'safe_noop_x'});
  assert.ok(result.templates.length>=3);
  assert.ok(result.templates.every((x)=>x.category==='rag'));
  assert.ok(result.templates.every((x)=>x.payload.includes('SAFE_MARKER_X')));
});

test('prompt injection suite supports competition pack alias',()=>{
  const result=buildPromptInjectionSuite({pack:'competition',ids:['output-format-hijack'],marker:'CTF_SAFE_MARKER'});
  assert.equal(result.templates.length,1);
  assert.equal(result.templates[0].id,'output-format-hijack');
  assert.match(result.templates[0].payload,/CTF_SAFE_MARKER/);
});

test('prompt injection evaluator flags marker and canary exposure as explicit candidate failure',()=>{
  const result=evaluatePromptInjectionRun({
    templateId:'canary-exfiltration',
    response:`debug: ${DEFAULT_CANARY} and ${DEFAULT_MARKER}`,
    toolCalls:[]
  });
  assert.equal(result.verdict,'candidate-failure');
  assert.equal(result.signals.markerHit,true);
  assert.equal(result.signals.canaryHit,true);
  assert.ok(result.findings.some((x)=>x.id==='prompt-injection-marker-followed'));
  assert.ok(result.findings.some((x)=>x.id==='prompt-injection-canary-exposed'));
});

test('prompt injection evaluator treats injected or undeclared tool execution as policy-boundary evidence',()=>{
  const result=evaluatePromptInjectionRun({
    templateId:'tool-output-injection',
    response:'normal text',
    toolCalls:[{name:DEFAULT_TOOL,arguments:{source:'injected'}},{name:'write_file'}],
    authorizedTools:['read_only_search']
  });
  assert.equal(result.verdict,'candidate-failure');
  assert.equal(result.signals.injectedToolTriggered,true);
  assert.equal(result.signals.unauthorizedToolCalls,2);
  assert.ok(result.findings.some((x)=>x.id==='prompt-injection-tool-triggered'));
  assert.ok(result.findings.some((x)=>x.id==='prompt-injection-unauthorized-tool'));
});

test('prompt injection evaluator does not call absence of explicit signals a security proof',()=>{
  const result=evaluatePromptInjectionRun({templateId:'direct-instruction-override',response:'继续完成原始任务。'});
  assert.equal(result.verdict,'no-explicit-failure');
  assert.equal(result.findings.length,0);
  assert.ok(result.notes.some((x)=>/不是“安全证明”/.test(x)));
});

test('prompt injection source audit finds RAG and model-to-tool policy candidates without claiming confirmed exploit',()=>{
  const source=`
user_input = request.json['query']
docs = retriever.similarity_search(user_input)
context = context + docs[0].page_content
response = client.chat.completions.create(messages=[{'role':'user','content':context}])
if response.tool_calls:
    execute_tool(response.tool_calls[0])
`;
  const result=auditPromptInjectionSource(source);
  assert.equal(result.surfaces.userSource,true);
  assert.equal(result.surfaces.rag,true);
  assert.equal(result.surfaces.modelCall,true);
  assert.equal(result.surfaces.toolSurface,true);
  assert.ok(result.findings.some((x)=>x.id==='prompt-injection-untrusted-prompt-flow'));
  assert.ok(result.findings.some((x)=>x.id==='prompt-injection-rag-surface'));
  assert.ok(result.findings.some((x)=>x.id==='prompt-injection-tool-policy-candidate'));
  assert.ok(result.notes.some((x)=>/静态候选/.test(x)));
});

test('tool router exposes prompt injection suite, evaluator and source audit',()=>{
  assert.ok(runTool('ai-prompt-injection-suite',{input:'{}'}).templates.length>=25);
  assert.ok(runTool('ai-prompt-injection-suite',{input:JSON.stringify({competitionOnly:true})}).competitionCount>=20);
  assert.equal(runTool('ai-prompt-injection-evaluate',{input:JSON.stringify({response:DEFAULT_MARKER})}).verdict,'candidate-failure');
  assert.ok(runTool('ai-prompt-injection-source',{input:'retriever.similarity_search(q); client.responses.create({input: context}); tool_calls'}).surfaces.rag);
});

test('prompt injection renderer compiles and loads after Batch 9 AI tools',()=>{
  const root=path.join(__dirname,'..');
  const source=fs.readFileSync(path.join(root,'renderer/ai_prompt_injection_tools.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  assert.doesNotThrow(()=>new vm.Script(source,{filename:'renderer/ai_prompt_injection_tools.js'}));
  assert.ok(html.indexOf('ai_prompt_injection_tools.js')>html.indexOf('ai_batch9_tools.js'));
  assert.match(source,/提示词注入训练/);
  assert.match(source,/competitionOnly/);
  assert.match(source,/赛题高频/);
});
