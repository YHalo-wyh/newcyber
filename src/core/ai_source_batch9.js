const base=require('./ai_source');
const { auditAiSupplyChain }=require('./ai_supply_chain');
const { auditPromptInjectionSource }=require('./ai_prompt_injection');

const FIXES=Object.freeze({
  'ai-output-shell-injection':{
    target:'AI/ASR output → shell command boundary',
    action:'改为固定可执行文件 + argv 数组；对模型输出使用结构化 schema/allowlist，不把输出拼入 shell 命令。',
    regression:'包含空格、引号、分号、$() 等控制字符的模型输出只能作为单独参数，不能改变命令结构；正常输入行为保持一致。'
  },
  'shell-sink':{
    target:'Shell sink 调用点',
    action:'优先使用 shell=false 的 argv 调用；必须 shell 时对可变字段做严格语义约束而非黑名单转义。',
    regression:'注入字符不能新增命令/管道/重定向，合法参数仍能正常执行。'
  },
  'unsafe-deserialization':{
    target:'pickle/joblib/torch.load 输入边界',
    action:'把不可信 artifact 改为 SafeTensors/纯权重格式；必须兼容 pickle 时在加载前固定来源/hash并做静态模型扫描。',
    regression:'含危险 GLOBAL/REDUCE 的构造样本必须在加载前被拒绝，正常 checkpoint 不受影响。'
  },
  'dynamic-code':{
    target:'eval/exec 动态执行点',
    action:'改成显式 parser / schema / dispatch table；模型输出、RAG 文本和用户输入都不得直接作为代码执行。',
    regression:'输入 Python/JS 语法片段时只作为数据处理，不能改变控制流。'
  },
  'prompt-concat':{
    target:'Prompt/context 组装边界',
    action:'把 trusted instruction 与 untrusted content 分离成明确字段/消息角色；工具调用前再做结构化授权。',
    regression:'把“忽略上文/调用工具”等内容放入文档或用户字段时，不能覆盖系统策略或直接触发高权限动作。'
  },
  'prompt-injection-untrusted-prompt-flow':{
    target:'Untrusted content → prompt/messages → model',
    action:'按真实消息角色分离 trusted instruction、user data、RAG context 和 tool output；不要依赖 XML/Markdown 分隔符本身充当安全边界。',
    regression:'direct/role-smuggling/delimiter-escape 模板不能改变系统策略；输出不得命中训练 marker/canary。'
  },
  'prompt-injection-rag-surface':{
    target:'RAG/retrieved context → model',
    action:'把检索片段视为不可信知识数据；系统授权逻辑、工具权限与秘密材料不得由检索文本决定。',
    regression:'indirect-document/rag-retrieval 模板进入 top-k 后，只能被总结/引用，不能升级为行为指令。'
  },
  'prompt-injection-tool-policy-candidate':{
    target:'Model/agent → tool dispatch',
    action:'在模型之外增加 tool allowlist、参数 schema、资源级权限检查和必要的人机确认；工具返回值再次按不可信数据处理。',
    regression:'tool-output-injection 模板不能触发 training_noop 或任何未声明 authorizedTools。'
  },
  'llm-derived-crypto-key':{
    target:'模型输出 → KDF/key derivation',
    action:'若该值用于安全边界，改用密码学随机源或独立 secret；模型输出只能作为非秘密业务数据。',
    regression:'固定 prompt/model 参数或枚举模型输出后，不能据此恢复长期密钥或解密历史密文。'
  },
  'llm-replay-parameters-exposed':{
    target:'业务接口中的 model/prompt/temperature 暴露',
    action:'只返回业务必要字段；安全相关生成链不要同时暴露足以复现密钥/令牌生成的完整参数。',
    regression:'普通客户端响应不再包含可复现安全令牌/密钥生成所需的完整模型参数。'
  }
});

function attachFix(finding) {
  if (finding.fix) return finding;
  const fix=FIXES[finding.id];
  return fix ? { ...finding, fix:{...fix} } : finding;
}

function auditAiChallengeSource(input) {
  const result=base.auditAiChallengeSource(input);
  const supply=auditAiSupplyChain(input);
  const promptInjection=auditPromptInjectionSource(input);
  const existing=new Set((result.findings||[]).map((x)=>`${x.id}:${x.line||0}`));
  const findings=(result.findings||[]).map(attachFix);
  for (const source of [supply,promptInjection]) {
    for (const finding of source.findings||[]) {
      const key=`${finding.id}:${finding.line||0}`;
      if (existing.has(key)) continue;
      findings.push(attachFix(finding));
      existing.add(key);
    }
  }
  const order={high:0,medium:1,low:2,info:3};
  findings.sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9)||(a.line||0)-(b.line||0));
  return {
    ...result,
    findings,
    supplyChain:supply,
    promptInjection,
    remediationSummary:{
      actionable:findings.filter((x)=>x.fix?.action).length,
      regressions:findings.filter((x)=>x.fix?.regression).length
    }
  };
}

module.exports={ ...base, auditAiChallengeSource, attachFix, FIXES };