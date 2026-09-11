# Batch95 · 训练质量门禁与有效覆盖

Batch95 不继续单纯增加 AI 赛题样本，而是先修正 NewCyber 训练体系里一个更关键的问题：**raw case 数量不等于有效训练覆盖**。

此前 `coverageDebt` 主要按方向的 case 数量判断缺口。这样存在明显误差：同一赛事、同一题目、同一 family 只要复制多个变体，就可能让数字看起来很充足，但对未知赛题的泛化价值并没有同步增加。

## 本批次新增

新增 `src/core/ai_training_quality.js`，对每个 AI 方向计算：

- `rawCases`：原始 case 数；
- `uniqueSignatures`：去重后的 event + challenge + family 组合数；
- `uniqueFamilies`：独立攻击/分析家族数；
- `uniqueEvents`：独立赛事/来源事件数；
- `uniqueChallenges`：独立题目数；
- `effectiveCases`：按 provenance 强度折算后的有效 case；
- `provenanceAverage`：来源证据质量；
- `duplicateRatio`：重复膨胀比例；
- `crossEventHoldoutReady`：是否已具备用跨赛事样本做 holdout 的基本条件；
- `qualityScore`：综合训练健康度；
- `readiness`：`seed / developing / ready`。

## 为什么这样比继续堆题更重要

例如某个方向有 8 个训练 case，但 8 个都来自同一题，只是 prompt、字段顺序或 fixture 有轻微变化。旧逻辑会认为该方向已达到 8 case；新逻辑会将它们折算成 1 个 signature，并提示：

- `reduce-duplicate-case-inflation`
- `add-distinct-families`
- `add-cross-event-evidence`
- `build-cross-event-holdout`

这能直接阻止“训练集看起来很大，比赛一换题型就失效”的假覆盖。

## Provenance 权重

Batch95 不把所有来源视为同等可靠。当前规则采用保守权重：

| 来源证据 | 权重 |
| --- | ---: |
| 官方题目归档 / challenge-source-specific | 1.0 |
| 具体赛题 WriteUp | 0.8 |
| benchmark / paper / research / public challenge | 0.7 |
| 普通公开 repository/archive | 0.6 |
| 只有 URL、缺少更具体证据等级 | 0.5 |
| 无明确 provenance | 0.25 |

`effectiveCases` 对相同 signature 只保留最高 provenance 权重，因此复制同题变体不会继续抬高有效覆盖。

## Ready 门槛

一个方向只有同时满足以下条件才允许标记为 `ready`：

1. 至少 3 个独立 family；
2. 至少 3 个独立 event；
3. 至少满足 cross-event holdout 的基本条件；
4. 综合 quality score 达标。

这不是在宣称 NewCyber 已经能解决所有未知题，只表示 curriculum 的覆盖结构已经具备较合理的泛化评估基础。

## 对 Privacy 方向的处理

本轮原计划继续补国内模型隐私赛题，但公开可确认的 Membership Inference / Model Inversion / Model Extraction 国内赛题资料仍明显少于 Prompt、对抗样本和投毒方向。

因此 Batch95 没有为了凑数量伪造 domestic replay，而是先让训练总线能明确暴露：

- Privacy 是否只有 benchmark，没有真实跨赛事证据；
- 是否只是同 family 重复；
- 是否真正具备 cross-event holdout 条件；
- 下一批应该补 family、event 还是 provenance。

之后 Batch96 再根据这个质量报告选择 Privacy 或 Supply Chain 的真实公开赛题来源。

## 接入位置

为避免破坏现有 UI、tool router 和历史测试，Batch95 **保留原有 schema 版本**：

- `newcyber.ai-training-curriculum.v1`
- `newcyber.ai-training-curriculum-regression.v1`

只做向后兼容的字段扩展：

- `summary.quality`
- `quality`

原有 `coverageDebt` 继续保留；但后续排序和训练优先级应优先参考 `quality.byDirection`，而不是 raw case 数量。
