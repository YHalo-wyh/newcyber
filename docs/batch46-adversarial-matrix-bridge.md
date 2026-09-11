# Batch46 · 对抗样本赛式排名接入统一五方向矩阵

Batch45 已经能单独运行 `ai-adversarial-contest-rank`，但如果用户把完整赛题 JSON 直接扔进 **AI Stage-One Bench**，原有 `ai-skill-matrix` 只认识 original/adversarial pair 与 batch scorer，赛式 `hints + candidates + logits` 仍然不会进入统一诊断。

Batch46 解决这个断层。

## 输入形式

统一矩阵现在额外识别：

- `adversarialContest`
- `adversarial_contest`
- `contestRanking`
- `contest_ranking`
- `adversarialRanking`
- `adversarial_ranking`
- 或者直接把同时包含 `hints` 与 `candidates/samples/rows`，且候选内存在 `scores/logits/output/predictionScores` 的对象作为输入

只有 `hint + candidate id` 而没有模型分数时不会误触发赛式排名。

## 状态语义

这是本批次最重要的约束：

**候选排名永远不会因为“第一名很像”就直接升级成 `evidence`。**

当所有 hint 都能形成候选组合时，对抗样本方向只进入：

`candidate / medium confidence`

矩阵会给出：

- hint 数量
- candidate 数量
- candidate set 数量
- unresolved hint 数
- ambiguous group 数
- 每组当前 top candidate id

下一步明确要求把 candidate sets 送到题目的真实 verifier/hash。只有真实判题闭环或等价 oracle 才能把结果视为验证证据。

## 兼容性

没有赛式输入时，继续调用原 `diagnoseAiSkillMatrix`，返回结构与之前一致：

- schema 仍为 `newcyber.ai-skill-matrix.v2`
- 不增加 `matrixRevision`
- 原 pair/batch adversarial 判定不改变

只有赛式扩展被激活时才增加：

- `matrixRevision: 3`
- `extensions: ['adversarial-contest-ranking']`
- `inputRouting.providedSlots += adversarialContest`
- 对抗样本 skill 的 `tools += ai-adversarial-contest-rank`

这样不会为了新赛题训练破坏现有五方向回归。

## 下一步

目前统一矩阵已经能处理：

`已有 logits → hint 约束 → candidate beam → verifier 下一步`

后续继续接 Batch45 文档里规划的推理入口：

`ONNX / PyTorch 模型 → 批量样本 inference → logits → adversarialContest → AI Stage-One Bench`

项目已经存在隔离的 `onnxruntime-node` 本地 runtime 和 `ai:onnx-run` IPC，因此后续应复用现有 runtime，而不是再引入一套 Python/ONNX 执行链。重点会放在安全的样本预处理清单、批量推理输出适配与类别目录映射。
