# Batch99：训练采集任务单

Batch98 已经能回答“下一轮优先补哪条训练 track”，但调度结果仍然停留在方向级别。Batch99 把 scheduler 的高优先级任务继续下钻，转成可以直接执行和验收的训练采集任务单（work order）。

## 目标

训练闭环从：

`curriculum -> quality -> holdout -> schedule`

推进为：

`curriculum -> quality -> holdout -> schedule -> work order -> evidence -> synthetic regression -> quality/holdout recompute`

work order 不代表系统已经找到对应公开赛题，也不会臆造题目名称或机制。它只定义下一轮应该寻找什么公开证据，以及什么条件满足后才允许把新 case 接入 curriculum。

## 新增模块

`src/core/ai_training_work_orders.js`

支持七条 curriculum track：

- prompt-llm-security
- adversarial-example
- privacy-leakage
- model-extraction
- backdoor-poisoning
- dataset-pipeline-security
- infra-supply-chain

每个方向都有自己的 acquisition blueprint，包括：

- 推荐公开来源类型
- 可优先寻找的新 family 主题
- 最低证据要求
- synthetic verifier 设计建议
- positive / negative / control 最低回归结构

## Work Order 结构

每个任务单包含：

- `id / rank / priority / score`
- `direction`
- scheduler 原始 objective
- `preferredSourceKinds`
- `familyThemes`
- `avoidExisting.events / families`
- `searchHints`
- `requiredEvidence`
- `regressionDesign.verifier`
- `fixturePolicy`
- `acceptanceGates`
- `prohibited`
- `completionProof`

### 关键设计

#### 1. 先证据，后 fixture

不能因为某个方向存在覆盖缺口，就自己编一个“看起来像 CTF”的训练样本。

任务单要求至少有公开来源能够支持：

- 挑战目标或威胁模型
- 输入 / 输出或行为结构
- 成功条件 / 检测条件
- control / baseline 的含义

只有这些结构有公开证据后，才生成 synthetic verifier fixture。

#### 2. synthetic regression 不复制真实答案

允许保留机制，但不能把这些东西直接塞进训练 corpus：

- 真实 Flag
- 密钥
- 未公开触发器
- 私有附件
- 泄漏数据
- 原题隐藏答案

fixture 必须换成 synthetic canary、synthetic logits、synthetic labels、synthetic predictions 等确定性数据。

#### 3. 每个 family 必须有 negative/control

只做 positive case 会让 evaluator 很容易退化成关键词命中器。

因此新增 case 至少要求：

- 1 positive
- 1 negative
- 1 specificity/control

#### 4. 完成标准不是“新增文件”

work order 只有在重新计算后才算真正完成：

- quality debt 降低
- holdout 不出现 leakage
- event/family 覆盖增加
- 若目标要求 unseen-family，则至少出现一条 clean unseen-family holdout plan
- schedule 中对应方向的优先级/score 应下降，或者 readiness 得到提升

## Curriculum 与 Tool Router

`getTrainingCurriculum()` 继续保持：

`newcyber.ai-training-curriculum.v1`

新增：

- `summary.workOrders`
- `workOrders`

新的独立工具：

`ai-training-work-orders`

可传：

```js
{ options: { limit: 3 } }
```

或：

```js
{ options: { direction: 'privacy-leakage', limit: 1 } }
```

## Stage-One Bench

训练健康面板现在增加 `ACQUISITION ORDER` 区域，显示当前最高优先级 work order：

- 目标方向
- scheduler 下一动作
- 候选新 family
- 公开证据要求
- verifier 要求
- acceptance gates
- 数据硬约束

UI 仍保持紧凑，不把训练区做成大卡片 dashboard。

## 安全与数据边界

Batch99 仍遵守此前训练策略：

- public metadata / public writeup / official archive only
- synthetic deterministic regression fixture only
- no real flag
- no key
- no private attachment
- no unpublished trigger
- no unsupported challenge mechanics

调度器和 work order 负责决定“下一步该补什么证据”，但不会把来源不足的猜测自动升级成训练事实。
