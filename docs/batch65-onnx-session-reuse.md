# Batch65 — ONNX Session Reuse / Candidate Throughput

Batch64 解决了“模型怎么安全跑”的问题，Batch65 开始解决比赛现场更现实的性能问题：**不能对每一张候选图都重新创建一次 `InferenceSession`**。

原来的 `runOnnxModel()` 是严格的一次请求一次 Session，适合人工单次探测，但 Challenge Session 最多会处理数百个候选样本。模型初始化、图优化、EP 初始化往往比一次前向本身更重，逐候选重建 Session 会把时间浪费在初始化上。

## 新增 `runOnnxRequests`

`local_ml_runtime` 新增：

```js
await runOnnxRequests(modelPath, requests, {
  provider: 'cpu'
})
```

语义：

- 整批请求只创建 **1 个** `InferenceSession`；
- 请求按顺序执行，默认不并发抢内存；
- 单个候选失败会被隔离为该行 error，后续候选继续；
- 可用 `failFast:true` 在首个错误处停止；
- 最终始终通过 `finally` 释放 Session；
- 每个成功结果仍保持原有 `newcyber.onnx-run.v1` 输出结构，所以现有 ranking / score-space / verifier 不需要改协议；
- 批次本身返回 `newcyber.onnx-request-batch.v1`，记录 requested/completed/succeeded/failed/sessionCreates/elapsedMs；
- 批量请求硬上限 2048，单 tensor / 输出上限继续沿用原 runtime 限制。

## 为什么先做 runtime primitive

这一步故意不偷偷改变 `runOnnxModel()` 的生命周期。已有单次工具、SCA、Transformer 相关模块依赖它“调用结束即释放”的行为，直接在底层加隐式全局 Session cache 容易产生模型文件变更、EP 状态和 native memory 生命周期问题。

因此 Batch65 先提供**显式、安全、可测试**的 Session reuse primitive；Challenge Session 的候选推理可以在下一层批量准备 feed 后一次性交给它，不需要引入隐式缓存。

## 回归保障

测试验证：

- 4 个候选只创建 / 释放 1 次 Session；
- 中间一个坏候选不会导致重建 Session，也不会阻断后续候选；
- `failFast` 正常工作并释放 native Session；
- 请求数量超过上限会在创建 Session 之前拒绝；
- 原 `runOnnxModel()` 的单次行为和 `newcyber.onnx-run.v1` schema 保持不变。
