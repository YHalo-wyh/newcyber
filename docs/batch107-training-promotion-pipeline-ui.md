# Batch107 — Training Promotion Pipeline Workbench

Batch100–106 已经形成完整的 evidence → regression → integration → transaction → promotion 链路，但此前只有 Evidence Intake / Skeleton 暴露在 `tool_router`，后续门禁主要停留在核心模块与测试里。Batch107 把这些能力接回 Stage-One Bench，同时保留 repository/CI 安全边界。

## 新增

- `src/core/ai_training_pipeline_status.js`
- `renderer/ai_training_pipeline_ui.js`
- `renderer/styles/ai_training_pipeline.css`
- `tests/batch107-training-promotion-pipeline-ui.test.js`

并更新：

- `src/core/tool_router.js`
- `renderer/toolbox.html`

## Tool routes

Batch107 新增正式路由：

- `ai-training-regression-materialize`
- `ai-training-integration-gate`
- `ai-training-integration-writer`
- `ai-training-integration-verify`
- `ai-training-transaction-manifest`
- `ai-training-promotion-manifest`
- `ai-training-promotion-validate`
- `ai-training-promotion-pr-request`
- `ai-training-promotion-merge-authorize`
- `ai-training-pipeline-status`

Materializer 的 evaluator 通过现有 `runTool()` 同步调用，因此仍走 NewCyber 已有确定性分析器，不新增网络执行面。

## 刻意不暴露的 route

没有增加 `ai-training-transaction-execute`。

Batch105 的 transaction executor 依赖 repository adapter、真实分支、真实 HEAD、写文件、执行测试和加载 persisted curriculum。这一层不能被 renderer 的一个按钮伪装成“已经验证”。Stage-One UI 只能生成/检查 manifest 和状态；真正事务执行继续由隔离分支工作流承担。

## Stage-One 工作台

在现有 `TRAINING HEALTH / NEXT ROUND / ACQUISITION ORDER` 下方新增 `TRAINING PROMOTION PIPELINE`。

用户可以：

1. 按当前 top Work Order 生成 Evidence Intake 模板；
2. 填入公开来源、mechanics summary、success condition、negative control 与 synthetic verifier；
3. 运行 Evidence Intake；
4. 生成 Regression Skeleton；
5. 在 JSON 编辑器内补齐三个 synthetic fixture 的 payload、predicate、assertions；
6. 运行 Materializer dry-run；
7. 运行 Integration Gate，确认候选真的带来 event/family/holdout 结构增益；
8. 后续 Writer / Transaction / Promotion / Merge 作为 repository-bound 阶段继续显示，但不能从 UI 绕过 source SHA、base/head SHA、tests、full regression 和 CI proof。

每一步返回的 JSON 会直接成为下一步编辑输入，所以 fixture 可以在同一工作区修订，而不需要在多个工具页面之间复制。

## Pipeline status inspector

`inspectTrainingArtifact()` 能识别 Batch100–106 的 schema，并统一输出：

- 当前 stage
- state
- next route
- blockers
- 八阶段状态轨
- `local-deterministic` / `repository-bound` 安全边界

这让 renderer 不需要自己推测每个后端 schema 的安全含义。

## 安全约束

工作台不会降低现有训练策略：

- 公开来源证据优先；
- fixture 必须 synthetic；
- 真实 Flag、私钥、Token、未公开触发器不进入 corpus；
- raw case 数量不能替代结构覆盖；
- Integration Gate 仍要求 event/family/holdout 的 meaningful structural gain；
- repository write / transaction / promotion / merge 都必须继续走 Batch104–106 的显式凭证链。
