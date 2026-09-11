# Batch97 · Stage-One 训练覆盖健康度 UI

Batch95 已经能判断训练 corpus 的质量，Batch96 已经能生成真正的跨赛事 holdout，但这两组数据此前只存在于 `ai-training-curriculum` 的 JSON 结果里。Batch97 把它们接到 Stage-One Bench 右侧训练区域，让“下一步该补什么”直接可见。

## UI 目标

新增 `TRAINING HEALTH / 训练覆盖健康度` 区域，读取：

- `quality.summary / quality.byDirection`
- `holdout.summary / holdout.byDirection`

顶部给出：

- overall quality score
- ready track 数量
- holdout eligible track 数量
- unseen-family holdout 数量

每个官方一阶段方向显示：

- `种子 / 建设中 / 可评估`
- 有效样本 / 原始样本
- 最弱子轨的 event / family 数量
- clean holdout 数量
- unseen-family holdout 数量
- 当前最优先补齐的缺口

如果 Batch95 认为某条 track 已经 `crossEventHoldoutReady`，但 Batch96 实际无法生成 eligible holdout，UI 会显式显示“门禁与实际 holdout 不一致”，避免只看静态门禁。

## 七条 curriculum track → 五个官方方向

Stage-One Bench 仍保持五方向，不为了后端训练轨迹把 UI 扩成七张卡片。

聚合关系：

- 提示词工程与大模型安全 → `prompt-llm-security`
- 对抗样本攻击 → `adversarial-example`
- 模型隐私与数据泄露 → `privacy-leakage + model-extraction`
- 模型后门与数据投毒 → `backdoor-poisoning + dataset-pipeline-security`
- AI 基础设施与供应链安全 → `infra-supply-chain`

对包含多个子轨的方向，readiness 采用更保守的“最弱子轨”状态；event/family 也显示最弱子轨计数，避免把两条子轨简单相加后制造虚假的覆盖感。有效样本、clean holdout、unseen-family holdout 则用于展示已有训练资产总量。

## 实现方式

为了不扰动已经稳定的 `ai_skill_matrix_tools.js`，Batch97 新增一个轻量 renderer overlay：

- `renderer/ai_training_health_ui.js`
- `renderer/styles/ai_training_health.css`

该 overlay 在 `ai_skill_matrix_tools.js` 之后加载，只对 `ai-skill-matrix` 页面注入训练健康区域，不改变现有 Stage-One 分析、回归、国内赛题 replay 的行为。

数据通过现有 `ai-training-curriculum` tool route 读取，因此不新增 schema，也不复制 Batch95/96 的计算逻辑。

## 数据语义

这个面板仍然只描述 curriculum 健康度，不代表底座模型已经能自动解决未见赛题。

- `raw` 不能直接代表覆盖能力；
- `effective` 已考虑重复 signature 和 provenance 权重；
- `H` 只表示 clean cross-event holdout 计划；
- `U` 表示其中至少包含训练侧未见 family 的更严格测试；
- `ready` 是 corpus 结构门禁，不是比赛自动解题率。

真实 Flag、密钥、隐藏答案、未公开附件和未经证实的赛题机制仍不进入训练 corpus。