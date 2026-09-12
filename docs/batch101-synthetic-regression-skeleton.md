# Batch101 — Accepted Evidence → Synthetic Regression Skeleton

Batch101 把 Batch100 的 `accept` 结果继续转成可实现的 deterministic regression 脚手架，但不会伪造真实赛题数据。

## 输入门禁

生成器只接受 `newcyber.ai-training-evidence-intake.v1` 且 `verdict=accept` 的结果。`needs-evidence` 与 `reject` 都直接返回 `blocked`。

## 输出

`newcyber.ai-training-regression-skeleton.v1` 包含：

- evaluator tool / module / entrypoint 建议；
- normalized corpus entry 草稿；
- positive / negative / control 三个 synthetic fixture 槽位；
- fixture contract；
- 建议 corpus / test / doc 文件名；
- `node:test` 测试骨架；
- 完成门禁。

## 安全设计

所有 fixture `payload` 默认保持 `null`，测试默认 `test.skip`。这不是缺功能，而是硬门禁：没有足够公开证据时不允许自动编造输入、触发器、标签、阈值、Flag、密钥或隐藏答案。

只有在 synthetic fixture 已填充、positive predicate 有公开证据依据、negative/control 能证明特异性后，才能去掉 `test.skip` 并进入正式回归。

## Evaluator 映射

默认复用 NewCyber 已有工具：

- prompt / agent → `ai-prompt-injection-evaluate`
- adversarial → `ai-adversarial-batch`
- privacy → `ai-privacy-audit`
- model extraction → `ai-model-extraction`
- backdoor → `ai-backdoor-behavior`
- dataset pipeline → `ai-dataset-security`
- supply chain → `ai-supply-chain`

同时有 family-specific 覆盖：

- privacy + inversion → `ai-model-inversion`
- backdoor-poisoning + poison/label/loss/corrupt → `ai-poisoning-impact`

## Tool Router

新增：

```text
ai-training-regression-skeleton
```

可以直接传 Batch100 的 intake result，也可以传 candidate evidence；后者会先自动走 Evidence Intake，再决定是否生成 skeleton。

## 完成门禁

1. 三类 synthetic fixture 都必须填充；
2. positive predicate 只能来自公开 success condition；
3. negative/control 必须保持 non-finding；
4. 去掉 `test.skip`；
5. 全量测试通过；
6. provenance 与 fixture 分离；
7. 重新计算 curriculum quality / holdout / schedule，并记录 delta。
