# Batch105 — Transactional Integration Executor

Batch105 把 Batch104 的 deterministic write plan 变成隔离分支上的事务式集成执行流程。

## 目标

只有在以下条件全部成立时，才允许把一次训练样本集成推进到最终 PR：

1. Batch103 integration gate 已经返回 `ready-to-integrate`。
2. Batch104 writer 已经生成 `ready-to-write` write plan。
3. 当前仍处于预期 base branch。
4. base HEAD SHA 未漂移。
5. `ai_training_curriculum.js` 源码 SHA-256 未漂移。
6. 当前 curriculum case 集合 digest 未漂移。
7. 所有待创建 artifact 路径仍不存在。
8. 所有 writes 只在新建隔离分支中执行。
9. repository tests 通过。
10. full curriculum regression 通过。
11. 实际持久化 curriculum delta 与 Batch103 模拟 delta 完全一致。

只有最后一步验证成功，执行器才返回：

```text
status: verified-on-isolated-branch
finalization.allowed: true
finalization.action: open-integration-pr
```

执行器本身不会 merge `main`。

## 新增模块

`src/core/ai_training_transactional_integration.js`

主要导出：

- `digestCases(cases)`
- `isolatedBranchName(candidate,key)`
- `validateAdapter(adapter)`
- `buildTransactionManifest(...)`
- `preflight(manifest,adapter)`
- `executeTransactionalIntegration(...)`

## 为什么同时锁 source hash 和 cases digest

只锁 `src/core/ai_training_curriculum.js` 不够。

某个已经注册的 corpus module 可能在 registry 文件不变的情况下修改自己的 `getTrainingCorpus()` 返回值。这样：

- curriculum source SHA 不变；
- 真实 cases 已经改变；
- Batch103 的 quality / holdout / scheduler 模拟基线已经失效。

因此 Batch105 会对归一化后的 case 集合计算稳定 SHA-256 digest。digest 覆盖：

- id
- event
- challenge
- direction
- family
- caseType
- evaluator
- coverage
- trainingPolicy
- provenance

排序后再稳定序列化，因此 case 顺序变化不会产生误报，但证据级别等语义变化会被检测出来。

## 隔离分支

分支名由 candidate 的：

```text
event + challenge + family + stable key
```

确定生成，例如：

```text
training-integration/event-d-c4-memorization-canary-a1b2c3d4e5
```

事务执行顺序：

```text
preflight
  -> create isolated branch
  -> checkout isolated branch
  -> create corpus/test/doc
  -> update curriculum registry
  -> repository tests
  -> reload persisted curriculum
  -> full curriculum regression
  -> Batch104 verifyIntegratedResult
  -> authorize final integration PR
```

## 失败语义

### `preflight-failed`

发生在任何 repo mutation 之前，例如：

- base branch 漂移
- base HEAD 漂移
- curriculum source SHA 漂移
- case digest 漂移
- artifact path 突然被占用

### `tests-failed`

write 已经发生在隔离分支，但 repository tests 未通过。不会产生 finalization authorization，也不会污染 `main`。

### `verification-failed`

repository tests 通过，但真实 curriculum 与模拟结果不一致，例如：

- candidate 注册多次
- case count 不是严格 +1
- sourceErrors 出现
- full regression 失败
- quality / holdout / schedule delta 漂移

### `verified-on-isolated-branch`

只有所有检查都通过才会出现。此时只代表“允许开最终 integration PR”，仍然不等于已经 merge。

## Repository Adapter

执行器不把 GitHub、git CLI 或本地文件系统硬编码到核心逻辑中，而是通过 adapter 注入：

```text
getCurrentBranch
getHeadSha
readText
pathExists
createBranch
checkoutBranch
createText
updateText
runRepositoryTests
loadCurriculum
runFullRegression
```

这样同一套事务逻辑可以用于：

- GitHub connector
- 本地 git workspace
- Work/Computer Use runner
- 后续 CI bot

测试中使用 deterministic fake adapter 覆盖完整成功链与漂移/失败场景。

## Batch100–105 闭环

```text
Evidence Intake
  -> Regression Skeleton
  -> Regression Materializer
  -> Integration Gate
  -> Integration Writer
  -> Transactional Integration Executor
```

至此训练样本从公开证据进入 NewCyber 的流程已经具备：证据门禁、合成回归、模拟影响评估、确定性 patch、隔离执行和真实 post-write 验证。