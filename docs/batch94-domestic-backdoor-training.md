# Batch94 · 国内后门 / 投毒赛式训练扩展

Batch94 不继续堆 Prompt Injection 模板，而是补齐 Stage-One 五方向中相对薄弱的 **模型后门与数据投毒** 国内赛式训练。

## 为什么补这个方向

当前 NewCyber 已有通用后门 / 投毒分析器，也有 NIST TrojAI、BackdoorBench、公开 poisoning benchmark 等公共训练基线，但国内赛题回放主要集中在提示词安全和对抗样本。训练能力与比赛语境之间仍有一层断档。

本批次增加三类互补赛式：

| 公开来源 | 题型 | 训练家族 | 核心 verifier |
| --- | --- | --- | --- |
| 2026 软件系统安全赛总决赛 · CIFAR-10 | 分类模型后门激活 | image-trigger-backdoor-target-asr | clean / triggered / neutral-control 三组预测，目标 ASR + trigger specificity |
| 2025 gyxxaqjnds Finals · 投毒检测靶场 | loss-history 投毒检测 | loss-history-poison-ranking | loss 历史异常排序 + truth 集合独立复算 |
| CCB2025 · easy_poison 公开 WP | 标签交换型数据投毒 | label-swap-poisoning-impact | label flip + baseline/suspect 性能退化 |

## 训练原则

### CIFAR-10 后门题

官方归档只能确认：题目给出一个被怀疑存在后门的 CIFAR-10 分类模型，目标是找到并激活后门。

因此 Batch94 **不会猜原题 trigger**，也不会保存原题模型或 Flag。训练 fixture 只构造透明的预测对照：

- clean 输入维持正常预测；
- synthetic triggered 输入集中迁移到目标标签；
- neutral control 不产生同样迁移。

回归必须同时看到 `backdoor-target-asr-candidate` 与 `backdoor-control-specificity` 才算正例通过。这样避免把普通 OOD 敏感性误判成后门。

### loss-history 投毒检测

复用现有 `evaluateLossHistoryPoisonReplay()`：按相邻 loss 的 mean absolute change 做透明排序，并通过合成 truth 集合验证 top-k 是否恢复投毒样本。

这里明确不宣称该统计量等同原题隐藏实现，只训练“根据 loss 历史做异常排名 + 用独立 scorer 校验”的比赛结构。

### easy_poison

公开 WP 描述了标签交换型投毒结构。Batch94 只训练两层证据：

1. 污染子集中观察到大量 label flip；
2. suspect 指标相对 baseline 出现明显退化。

只有标签变化、没有模型影响时，不把结果升级成“攻击成功”。

## 负样本

三类赛式均加入对应 control：

- 后门：triggered prediction 与 clean 保持一致；
- loss-history：所有样本变化平滑，异常排序无法恢复 truth；
- 标签投毒：恢复原标签，同时 suspect 指标与 baseline 相同。

回归只有正例识别、负例不误报同时成立才算 PASS。

## 接入训练总线

Batch94 新增 `domestic-backdoor-poisoning-2025-2026` corpus，并接入：

- `getTrainingCurriculum()`
- `runTrainingCurriculumRegression()`

因此现有 `ai-training-curriculum` / `ai-training-full-regression` 路线会自动统计并执行这一批训练，不需要额外维护第二套总入口。

真实 Flag、触发器、模型权重、原题答案不进入训练 fixture。PASS 只表示 NewCyber 能解释这一类证据结构，不表示已经自动攻破原比赛题。
