module.exports = [
  {
    id: 'ai.prompt-trust-boundary', track: 'ai', domain: '人工智能', title: 'Prompt / Context 信任边界',
    tags: ['prompt-injection', 'system-prompt', 'rag', 'tool'],
    summary: '不可信输入进入 system/user prompt、RAG context 或工具参数时，重点追踪“输入 → 模型 → 高权限 sink”，而不是只看模型能否被越狱。',
    evidence: ['外部文本直接拼接 prompt/context', '模型输出进入工具、shell、文件、数据库或网络动作'],
    prerequisites: ['能区分 trusted instruction 与 untrusted content'],
    verify: ['构造最小输入改变模型输出并观察 sink 是否受影响'],
    falsePositives: ['模型输出只展示给用户且经过严格编码/确认'],
    actions: ['画 source→model→sink 数据流', '优先检查无人工确认的高权限动作'],
    mutations: ['prompt-role-reorder', 'indirect-document-injection', 'tool-output-injection']
  },
  {
    id: 'ai.output-to-sink', track: 'ai', domain: '人工智能', title: '模型输出到危险 Sink',
    tags: ['shell', 'subprocess', 'eval', 'sql', 'xss', 'agent'],
    summary: '模型输出只要被当作命令、代码、SQL、路径或富文本执行，就应按普通数据流漏洞审计。核心是 sink 语义，不是模型品牌。',
    evidence: ['subprocess_shell/os.system/eval/exec/SQL/HTML sink', '输出未做结构化约束直接进入 sink'],
    prerequisites: ['模型输出可被攻击者影响'],
    verify: ['最小 payload 能改变 sink 语义而非仅改变显示文本'],
    falsePositives: ['argv 数组固定命令且模型输出只作为单独参数'],
    actions: ['识别 sink 类型', '检查 escaping/schema/allowlist/confirmation'],
    mutations: ['sink-api-alias', 'argv-vs-shell', 'structured-output-wrapper']
  },
  {
    id: 'ai.model-serialization', track: 'ai', domain: '人工智能', title: '模型文件与反序列化攻击面',
    tags: ['pytorch', 'pickle', 'safetensors', 'npy', 'model'],
    summary: '对 .pt/.pth/NPY object 等格式优先做静态结构审计，识别 pickle GLOBAL/STACK_GLOBAL、storage 和异常 metadata，不直接加载不可信模型。',
    evidence: ['PyTorch ZIP 中 data.pkl', 'NPY object dtype', 'pickle 引用危险 global'],
    prerequisites: ['能够静态读取容器与 opcode'],
    verify: ['危险 global 确实可达 REDUCE/调用语义', '普通 torch rebuild global 不误报高危'],
    falsePositives: ['正常 tensor rebuild 与 storage 引用'],
    actions: ['列出危险 globals', '关联训练日志/参数结构异常'],
    mutations: ['pickle-global-substitution', 'object-dtype', 'storage-name-change']
  },
  {
    id: 'ai.nonfinite-boundary', track: 'ai', domain: '人工智能', title: 'NaN / Inf 数值边界',
    tags: ['nan', 'inf', 'json', 'model-input', 'validation'],
    summary: '数值模型/API 常在范围比较、归一化、排序或树模型路径上对 NaN/Inf 处理不一致。先验证解析层和校验层是否接受非有限值，再看模型语义。',
    evidence: ['输入为浮点数组/JSON', '比较逻辑未显式 isfinite'],
    prerequisites: ['语言/JSON parser 实际允许 NaN/Infinity 或可通过其他编码到达'],
    verify: ['确认非有限值穿过验证并改变模型/规则结果'],
    falsePositives: ['标准 JSON 严格拒绝 NaN，或入口显式 finite check'],
    actions: ['测试 NaN/+Inf/-Inf 边界', '记录 API parser 与模型处理差异'],
    mutations: ['nan-inf-json', 'missing-value-tree-path', 'normalization-boundary']
  },
  {
    id: 'ai.statistical-evasion', track: 'ai', domain: '人工智能', title: '统计异常检测规避',
    tags: ['isolation-forest', 'anomaly', 'covariance', 'features', 'evasion'],
    summary: '面对异常检测或多维风控，不能只逐列贴近均值；应保留边际分布、相关性和联合结构，再在业务目标约束下找候选。',
    evidence: ['公开正常样本 CSV/TSV', '高维数值特征', 'IsolationForest/LOF/OneClassSVM 等模型语义'],
    prerequisites: ['有训练/参考数据或模型结构'],
    verify: ['候选在单变量分位区间和强相关 residual 上均合理'],
    falsePositives: ['只看均值/标准差会忽略协方差和离散特征'],
    actions: ['统计中位数/分位数/相关性', '用确定性候选评分缩小输入空间'],
    mutations: ['column-scale', 'correlation-break', 'feature-order-change', 'missing-value']
  },
  {
    id: 'ai.generation-oracle', track: 'ai', domain: '人工智能', title: '受约束生成 / 输出 Oracle',
    tags: ['generation', 'greedy', 'beam', 'target', 'token-budget'],
    summary: 'LLM 生成题先恢复 model、max_new_tokens、beam/temperature、输入长度和目标输出判定，再把题目转化为确定性搜索/约束问题。',
    evidence: ['生成参数硬编码', '目标字符串或 verifier 明确'],
    prerequisites: ['本地模型/推理代码可复现或至少 verifier 可静态恢复'],
    verify: ['同输入多次输出稳定或随机源明确'],
    falsePositives: ['随机采样时不能把单次输出当确定 oracle'],
    actions: ['提取 target/长度约束', '区分 deterministic greedy 与 stochastic search'],
    mutations: ['target-change', 'token-budget-change', 'beam-change', 'prompt-prefix-change']
  },
  {
    id: 'ai.rag-poisoning', track: 'ai', domain: '人工智能', title: 'RAG / 向量检索污染',
    tags: ['rag', 'embedding', 'vector-db', 'poisoning', 'retrieval'],
    summary: 'RAG 题的核心通常是检索信任链：谁能写入知识库、查询如何构造、top-k/相似度如何选择、检索文本是否被当成高优先级指令。',
    evidence: ['向量库/embedding/top-k', '用户可提交文档或间接影响 corpus'],
    prerequisites: ['能确定写入面或检索条件'],
    verify: ['污染文档稳定进入目标 query 的 top-k 并影响后续行为'],
    falsePositives: ['污染内容能被检索但仅作为引用，不影响工具/秘密'],
    actions: ['恢复 indexing/query pipeline', '构造最小高相似度 adversarial document'],
    mutations: ['embedding-neighbor', 'topk-change', 'instruction-position']
  },
  {
    id: 'ai.model-supply-chain', track: 'ai', domain: '人工智能', title: '模型 / 依赖供应链',
    tags: ['model-download', 'dependency', 'hash', 'revision', 'supply-chain'],
    summary: '检查模型、Tokenizer、adapter、依赖是否固定 revision/hash，以及加载路径是否允许本地覆盖、远端自定义代码或不可信 artifact。',
    evidence: ['from_pretrained 未固定 revision', 'trust_remote_code', '动态下载/插件加载'],
    prerequisites: ['加载行为可从源码恢复'],
    verify: ['确认攻击者能影响解析到的 artifact/repository/revision'],
    falsePositives: ['比赛环境中资源完全内置且 hash 固定'],
    actions: ['记录 artifact 来源和 hash', '优先检查 remote code / pickle 格式'],
    mutations: ['revision-unpinned', 'adapter-shadowing', 'local-path-precedence']
  }
];
