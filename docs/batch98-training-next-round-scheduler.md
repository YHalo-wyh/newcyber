# Batch98 · 下一轮训练调度器

Batch97 已经能看到每条 Stage-One 方向的 quality / holdout 健康度，但它仍然需要人工判断“下一轮到底先补哪条”。Batch98 把这个判断变成确定性的训练调度队列。

## 核心原则

调度器不按 raw case 数量排序，而综合考虑：

- readiness：seed / developing / ready；
- quality score；
- cross-event holdout 是否真正可执行；
- unseen-family holdout 是否存在；
- event / family 覆盖债务；
- effective cases；
- provenance 强度；
- duplicate ratio。

输出 schema：`newcyber.ai-training-schedule.v1`。

## 队列字段

每条方向得到：

- `rank`：下一轮优先级；
- `priority`：critical / high / medium / low；
- `score`：0-100 的缺口优先分；
- `nextAction`：最优先要补的动作；
- `actions`：全部待补动作；
- `acquisitionMode`：新 family、holdout enablement、unseen-family stress、provenance upgrade 或 cross-event evidence；
- `targets.newEvents`；
- `targets.newFamilies`；
- `targets.effectiveCaseDebt`；
- `targets.unseenFamilyHoldout`；
- 当前 quality / holdout 指标快照。

## 为什么不是自动抓任意数据

这里的 schedule 是“证据采集与 deterministic regression 的工作队列”，不是让系统无条件爬取互联网，也不是自动把真实 Flag、密钥、私有附件或原题触发器塞进训练集。

来源策略仍要求：

1. 官方 challenge archive / organizer source 优先；
2. 公开 writeup / public challenge evidence 次之；
3. regression fixture 只用合成数据；
4. 不保存真实 Flag、密钥、私有附件。

## Curriculum 接入

原 schema 保持不变：

- `newcyber.ai-training-curriculum.v1`
- `newcyber.ai-training-curriculum-regression.v1`

只新增：

- `summary.schedule`
- `schedule`

Tool router 同时提供 `ai-training-schedule`，可直接获取队列。

## UI

Stage-One Bench 的“训练覆盖健康度”里新增 `NEXT ROUND / 下一轮训练调度`：

- 显示前 5 条优先队列；
- 显示方向、缺口动作、采集模式、目标 event/family 增量；
- 显示 priority score；
- 保留原 Batch97 health 表格，不影响原诊断与 replay。

这样训练链路变成：

`样本数量 → provenance → 有效覆盖 → 跨赛事 holdout → 下一轮训练调度`
