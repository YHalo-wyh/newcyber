# Batch96 · Cross-event Holdout 泛化评估

Batch95 解决的是“训练语料看起来很多，但其实可能只是同一题反复变体”的问题。Batch96 继续向前一步：把 `crossEventHoldoutReady` 从静态门禁变成真正可执行的 **leave-one-event-out** 评估计划。

## 核心目标

同一赛事里的题目经常共享叙事、数据格式、工具链甚至作者习惯。如果训练集和测试集来自同一 event，即使 challenge 名称不同，也可能高估模型/分析器的泛化能力。

Batch96 因此要求：

- 每次完整留出一个 event 作为测试集；
- 被留出的 event 不能出现在 train；
- train/test challenge key 不得重叠；
- 默认训练侧至少保留 2 个其他 event；
- 区分“跨 event 但 family 已见”和“跨 event 且 family 未见”两种难度。

## 新模块

新增 `src/core/ai_training_holdout.js`。

输出 schema：

`newcyber.ai-training-holdout.v1`

每个 direction 会得到：

- `eligible`：当前 corpus 是否足够做跨赛事留出；
- `events / families / cases`：当前方向的数据结构；
- `plans`：每个可留出 event 对应的一组 train/test 计划；
- `knownFamilyPlans`：测试 family 在训练中已经出现；
- `unseenFamilyPlans`：测试集至少包含训练中从未出现的 family；
- `leakage.clean`：event 与 challenge 两级均没有泄漏。

## 为什么要区分 known / unseen family

`cross-event-known-family` 更接近“同类题换赛事/换包装”；它主要验证格式、叙事、数据布局变化下的稳定性。

`cross-event-unseen-family` 更严格：测试 event 中至少存在训练集从未出现过的 family。它不能证明系统已经具备开放世界泛化，但能暴露只会匹配已知题型模板的问题。

## 与 Batch95 的关系

Batch95 的 `quality.crossEventHoldoutReady` 只回答“这个方向有没有基本条件做 holdout”。

Batch96 的 `holdout` 则真正生成计划，并验证：

1. 留出 event 是否彻底隔离；
2. challenge 是否泄漏；
3. 可生成多少 clean plan；
4. 其中多少属于 unseen-family 泛化压力测试。

因此后续训练优先级不能只看 raw case，也不能只看 quality score。一个方向即便被标记为 `ready`，如果所有 holdout 都只是 known-family，仍然应该继续补充新的 family 与真实公开来源。

## Curriculum 接入

Batch96 继续保持历史 schema 不变：

- `newcyber.ai-training-curriculum.v1`
- `newcyber.ai-training-curriculum-regression.v1`

只新增向后兼容字段：

- `summary.holdout`
- `holdout`

这样现有 UI / tool router / 历史测试不需要迁移 schema。

## 安全与数据策略

Holdout 规划只使用现有 curriculum 的元数据字段（direction/event/challenge/family），不引入真实 Flag、密钥、隐藏答案、私有赛题附件或未经证实的解题机制。
