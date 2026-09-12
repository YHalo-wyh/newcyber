# Batch100 Evidence Intake / 证据录入与验收器

Batch100 补齐 Batch99 work order 之后的入口门禁。目标不是自动抓公开题目后直接写入 corpus，而是先把候选公开证据包标准化，并给出 `accept / needs-evidence / reject` 判定。

## 新模块

`src/core/ai_training_evidence_intake.js`

核心入口：

- `checkCandidate(input, context)`
- `buildIntakeTemplate(workOrder)`

## 判定模型

### accept

仅当以下结构性条件全部满足时才允许生成 `corpusDraft`：

- event / challenge / direction / family / mechanicsSummary 完整；
- source URL 是公开 HTTP(S) 地址；
- source kind 与 evidence level 可识别；
- 至少两条公开证据事实；
- 有公开 success condition 与 negative-control 证据；
- verifier 为 synthetic-only；
- verifier 同时定义 positive / negative / control；
- 能匹配当前 work order；
- 与现有 corpus 不重复 `event + challenge + family` 签名；
- 不携带真实 Flag、密钥、Token 等敏感答案材料。

`accept` 只表示证据包已具备进入 synthetic deterministic regression 构造阶段的结构条件，不代表 NewCyber 自动证明网页内容真实，也不允许基于未公开信息推断赛题机制。

### needs-evidence

没有硬阻断，但缺少公开来源、negative control、verifier plan、synthetic control 等材料时返回该状态。此状态不能生成可进入 corpus 的 draft。

### reject

以下情况直接拒绝：

- 重复的 event/challenge/family 签名；
- 不支持的训练方向；
- work-order direction 不一致；
- 输入中出现真实 Flag、private key、secret/token/password/answer 等禁止材料。

## Novelty / Debt 对齐

验收器同时报告：

- event 是否为该方向的新 event；
- family 是否为该方向的新 family；
- 是否帮助关闭当前 work order 的 event debt / family debt；
- family 是否命中 work order 推荐的 family theme。

这些指标用于排序和人工判断，但不会替代 provenance 和 verifier 门禁。

## Tool Router

新增：

- `ai-training-evidence-template`
- `ai-training-evidence-intake`

模板工具可按 `workOrderId` 或 `direction` 生成空白 intake 模板；模板只预填方向、候选 family 和 verifier blueprint，不预填任何未经验证的证据。

## 安全与数据边界

继续沿用前几轮规则：

- 只接受公开来源元数据；
- regression fixture 必须 synthetic；
- 不保存真实 Flag、密钥、隐藏答案、私有附件或未公开触发器；
- 不将公开 writeup 的最终答案复制为 regression oracle；
- 不根据模糊描述臆造 challenge mechanics。

## 闭环位置

当前训练链路变为：

`corpus -> quality -> holdout -> schedule -> work order -> evidence intake -> synthetic regression -> quality/holdout/schedule recompute`

Batch100 的作用是把“采集到一个看起来相关的公开案例”与“允许进入训练回归设计”彻底分开。
