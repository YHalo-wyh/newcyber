# Batch64 — 证据驱动的多输入 ONNX 自动求解

Batch64 把 Challenge Session 的本地模型链从“单输入分类模型”扩展到“一个候选主输入 + 若干题目显式给出的常量辅助输入”，并先修复 named-label hint 在 JSON 发现阶段被错误丢弃的回归。

## 目标

典型题目不一定只有 `input -> logits`。模型可能同时要求图像/NPY 主输入和 `temperature`、`mask`、`length`、`seed`、`condition` 等辅助张量。NewCyber 不能因为存在第二个输入就放弃，也不能凭输入名或常见模型习惯猜辅助值。

Batch64 只接受题目文本 JSON 中显式的输入证据：

```json
{
  "onnxInputs": {
    "temperature": {
      "type": "float32",
      "dims": [1],
      "values": [1.0]
    }
  }
}
```

支持的显式键为 `onnxInputs`、`onnx_inputs`、`inputFeeds`、`input_feeds`、`constantFeeds`、`constant_feeds`。普通 `feeds` 字段不会被自动提升为辅助输入证据，避免误把候选运行数据当控制配置。

## 安全边界

- 不执行题目 Python/JS，不导入 pickle，不从配置读取任意文件路径。
- 辅助 tensor type 只允许本地 ONNX runtime 已支持的数字/布尔类型。
- `dims`、元素数、`values` 数量、Base64 格式和解码后字节数都在推理前验证。
- 多个来源对同一输入给出不同值时标记 `INPUT_BINDING_CONFLICT`，停止自动执行。
- 对 image/NPY 自动模式，所有非主输入都必须有显式 binding；剩余两个及以上未绑定输入会停止，不猜哪个是主输入。
- binding 与 ONNX metadata 的 type/shape 不一致时模型判为不兼容。

## 自动链

1. 静态读取有界源码/JSON/CSV。
2. 恢复 hint、`class_to_idx`、candidate label/id 与 auxiliary ONNX bindings。
3. 用候选输入 shape + 辅助输入证据给所有 ONNX 模型打兼容性分。
4. 选择唯一/明显更优的模型；证据不足仍返回 `MODEL_AMBIGUOUS`。
5. 对 image/NPY 主输入执行既有 evidence-gated preprocessing。
6. 把主 tensor 与经过验证的辅助 tensor 合并后调用本地 `onnxruntime-node`。
7. named label 通过 `class_to_idx` 进入 score space。
8. 若 class map 是从 `0..C-1` 完整连续映射，则 `C` 可用于多个 `[C]` / `[1,C]` 输出之间的安全消歧；不完整映射不参与该判断。
9. Top-2 pair、margin、runner-up、beam ranking 生成候选集合。
10. 只有题目 verifier/hash recipe 精确命中才升级 `verified`。

## UI

Challenge Session 的 `AI MODEL AUTOPILOT` 卡片新增 `INPUT PLAN` 与 `LABEL SPACE`，可直接看到：

- 主候选输入名；
- 显式绑定的辅助输入数量与证据文件；
- candidate/class mapping 数量；
- score-space 状态与完整类别数；
- verifier recipe/match 状态。

这使“模型为什么能跑”“辅助输入从哪里来”“类别索引是否对齐”不再藏在黑箱里。
