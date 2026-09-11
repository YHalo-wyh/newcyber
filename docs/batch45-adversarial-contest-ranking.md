# Batch45 · 国内赛式对抗样本候选排名

本批次继续强化一阶段五方向中的 **对抗样本攻击**。目标不是再塞一个 FGSM / PGD 按钮，而是补比赛里更常见但之前缺失的一层：题目已经给出模型、样本、类别迁移提示和模型输出后，如何从大量候选中筛出真正的对抗样本，并把不确定性保留到最终 verifier。

## 公开来源

本批次以 2021 春秋杯新年欢乐赛 AI 题 `old_driver` 的公开 WriteUp 作为国内赛式结构来源：

- https://www.secpulse.com/archives/152955.html

公开题解描述的核心结构是：题目模型对原图生成对抗样本，成功样本被移动到新的类别目录；`hint1` 给出“原类别 → 当前/伪造类别”的映射。解题时，候选样本通常满足：

1. 模型 Top-1 为当前/伪造类别；
2. Top-2 为 hint 指定的原类别；
3. Top-1 与 Top-2 分差较小；
4. runner-up（原类别）仍有较强得分；
5. 最终候选编号组合还需要交给题目 hash/verifier 确认。

NewCyber 只复现这个 **判定结构**。训练 fixture 使用合成 logits 和合成编号，不保存原题图片编号、原题 Flag 或答案组合。

## 新增能力

新增 `src/core/ai_adversarial_ctf.js`：

- `rankAdversarialContestCandidates`：按 hint 对候选分组，先硬过滤 Top-2 类别关系，再按小 margin + runner-up 强度排名。
- `beam shortlist`：当 margin 与 runner-up 证据不完全一致时，不强行选一个样本，而是保留每组前 N 个候选并组合成有限 beam。
- `legacyOldDriverDigest`：只在候选编号可安全解析为整数时，复现公开 WP 中 `md5(str(sorted(ids)))` 的 verifier 序列化形式，作为最终核验辅助。
- `runOldDriverTrainingRegression`：8 个确定性检查，验证类别对过滤、候选排名、错误 runner-up 排除、组合 beam 和 hash 序列化。

工具路由：

- `ai-adversarial-contest-rank`
- `ai-old-driver-training-corpus`
- `ai-old-driver-training-regression`

## 为什么不直接选 margin 最小

公开 WP 本身就指出，只用“Top-1 / Top-2 分差最小”或者只用“第二名得分最高”都可能选错。Batch45 因此把两类证据拆开：

- **硬约束**：assigned class、Top-1、Top-2 必须和 hint 的目标/原类别关系一致；不满足直接排除。
- **软排序**：在硬约束候选里，用 `65% margin closeness + 35% runner-up strength` 排序，同时保留两个独立 rank。
- **不确定性**：如果证据竞争，保留 shortlist / beam，最终交给真实 verifier，而不是把 heuristic 当 ground truth。

这比“模型觉得它像对抗样本”更适合比赛，因为最终正确性仍然落在题目自己的判题规则上。

## Stage-One Bench

`AI Stage-One Bench` 的国内回放现在会跟随左侧方向切换：

- 提示词工程与大模型安全 → `i春秋赛题族 / RUN 12`
- 对抗样本攻击 → `old_driver 赛式排名 / RUN 8`
- 其余三个方向 → 保持 `PROVENANCE FIRST`，没有足够公开附件/WP/verifier 证据时不伪造国内赛题回归。

这样国内真题训练不会继续全部挤在 Prompt Injection 一栏里，五方向可以逐步各自沉淀赛式回放。

## 下一步

Batch45 先解决“**已有 logits 的候选识别**”。下一步更有价值的是把这层和模型执行接起来：读取题目给出的 PyTorch/ONNX 模型，对目录或 NPY 样本批量跑 inference，自动生成 `candidate.scores`，再直接进入本批次的 ranker。这样才能形成：

`题目模型 → 批量推理 → Top-K 关系 → hint 约束 → 候选 beam → verifier`

而不是要求用户先自己把 logits 手工抄成 JSON。
