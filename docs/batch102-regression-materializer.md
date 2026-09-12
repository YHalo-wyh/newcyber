# Batch102 — Regression Materializer

Batch101 只生成安全脚手架：fixture payload 为空、测试保持 `test.skip`。Batch102 增加实体化门禁，用于把**已经人工填好的 synthetic fixture**验证成可提交工件。

## 输入门禁

Materializer 只接受 `newcyber.ai-training-regression-skeleton.v1` 且 `status=ready` 的 skeleton，并要求：

- positive / negative / control 各且仅各一条；
- 每条 fixture 显式 `synthetic: true`；
- payload 不再为空；
- `expected.predicate` 不得保留 TODO；
- 每条 fixture 必须提供声明式 `expected.assertions`；
- fixture payload 通过 secret pattern 扫描。

当前 secret 扫描覆盖 CTF flag 形态、私钥、JWT、GitHub token、OpenAI key、AWS access key 等明显真实凭据模式。扫描目的不是判断某个字符串“真假”，而是确保训练回归中不直接承载常见真实秘密格式。

## 声明式断言

支持：

`eq / neq / truthy / falsy / exists / not-exists / gt / gte / lt / lte / includes / not-includes / length-eq`

断言通过 `path` 从 evaluator 结果中取值，例如：

```js
{ path: 'metrics.auc', op: 'gte', value: 0.8 }
```

这样 Materializer 不需要猜测不同 evaluator 的 finding 字段，也不会把“positive 必须长什么样”硬编码成脆弱的通用规则。

## Dry-run

`materializeRegression(skeleton, executeTool)` 会对三条 fixture 调用 skeleton 已选择的 evaluator，并逐条执行声明式断言。任何 evaluator 异常、异步返回、断言失败都会得到 `dry-run-failed`，且**不产出 artifacts**。

只有三条 fixture 全部通过时返回：

```text
status: ready-to-commit
readyToCommit: true
```

并生成：

- corpus module 内容；
- 去掉 `test.skip` 的真实 `node:test` 回归内容；
- provenance / dry-run 说明文档内容。

## 安全边界

`ready-to-commit` 只表示：给定 synthetic fixture 在本地选定 evaluator 上满足其显式断言。它不替代 Batch100 的公开证据真实性检查，也不证明原赛题存在未公开机制。

实体化之后仍必须：写入工件、执行完整 `npm test`、注册 corpus、重新计算 curriculum quality / holdout / schedule，才算真正完成训练闭环。
