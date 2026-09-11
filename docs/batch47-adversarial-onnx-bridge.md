# Batch47 · ONNX 推理结果直连赛式对抗样本排名

Batch45 已经解决 `logits → hint → Top-2 → beam → verifier`，Batch46 又把这一层接进统一五方向矩阵。还缺的一步是：**不要让用户手工把模型输出抄成 scores**。

项目本来就已经有隔离的 `onnxruntime-node` 本地 runtime、显式模型选择器和 `ai:onnx-run` IPC，因此 Batch47 不再引入第二套 Python 推理环境，而是直接复用现有安全边界。

## 新增核心桥接

`src/core/ai_adversarial_onnx_bridge.js` 增加：

- `chooseScoreOutput`：从 `newcyber.onnx-run.v1` 结果中安全选择分类输出。
- `adaptOnnxRunsToContestBundle`：把多个 ONNX run 结果转成 Batch45 的 `{id, assignedLabel, scores}` candidate。
- `rankAdversarialContestFromOnnxRuns`：直接进入赛式 Top-2 / margin / runner-up / beam 排名。

新增工具路由：

- `ai-adversarial-onnx-adapt`
- `ai-adversarial-onnx-rank`

## 为什么严格限制输出 shape

`local_ml_runtime` 为避免把巨量模型输出直接塞回 Renderer，只保留有限 preview。因此 Batch47 明确禁止两种偷懒：

1. `truncated=true` 时，绝不把 preview 当成完整 logits；
2. 自动模式只接受 `[C]` 或 `[1,C]`，不自动 flatten feature map / embedding / detection head。

如果模型有多个可用向量输出，则要求显式指定 `outputName`。名称中只有一个 `logits / scores / probabilities` 风格输出时才允许自动选择。

这比“随便拿第一个 output”麻烦一点，但比赛里拿错 head 会直接把后续排名带沟里，省这一步属于经典省小钱亏大分。

## 新增 UI 工作台

AI 工具箱新增 **ONNX 对抗样本批量排名**：

1. 点击 `选择 ONNX`，走已有受控模型选择器；
2. 输入 `hints` 和 candidate tensor feeds；
3. 点击 `RUN ONNX + RANK`；
4. Renderer 逐候选调用已有 `runOnnxModel`；
5. 完整分类向量通过 `ai-adversarial-onnx-rank` 适配并排名；
6. 输出每个 hint 的 shortlist、margin、runner-up probability、suspicion score，以及前若干 candidate sets / legacy digest。

UI 单次限制 512 个候选，执行过程复用系统任务进度条。tensor feed 完全沿用本地 runtime 的 spec：

```json
{
  "input": {
    "type": "float32",
    "dims": [1, 3, 32, 32],
    "base64": "..."
  }
}
```

也可以使用 `values`，但大样本优先使用 base64，避免巨型 JSON 数组拖垮 Renderer。

## 仍然没有做的事情

Batch47 解决的是 **已预处理 tensor → ONNX → logits → contest ranker**。

它暂时不猜原图应该怎么 resize / normalize / channel-order，因为这些规则必须跟题目 verifier 一致。自动“看模型 shape 就猜 ImageNet normalization”听起来聪明，实战里很容易送命。

下一批更合理的是做 **preprocessing manifest**：由源码/题目配置提取 `layout、resize、scale、mean、std、RGB/BGR`，先生成可审计清单，再把 PNG/JPEG/NPY 自动转换成 tensor feeds。只有 preprocessing 有明确证据时才自动跑整目录。
