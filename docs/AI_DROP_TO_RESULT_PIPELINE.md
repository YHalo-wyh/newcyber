# NewCyber AI Drop-to-Result Pipeline

> 目标：把 AI 安全赛题附件或压缩包直接丢进 NewCyber，尽可能自动完成安全展开、证据识别、题型路由、模型/数据分析、候选生成与 verifier 闭环；当证据不足时明确输出 GAP，而不是猜答案。

## 1. 当前主链

```text
Challenge archive / files
        |
        v
[1] Safe Archive Ingest
        |
        v
[2] Workspace Evidence Scan
        |
        v
[3] Recovered Artifact Fixed Point
        |
        +-------------------------------+
        |                               |
        v                               v
[4] AI Preprocessing Evidence     [5] Training Family Match
        |                               |
        v                               v
[6] Local ONNX / Prepared Tensor  [7] Strategy Reuse
        |                               |
        +---------------+---------------+
                        |
                        v
[8] Contest Bundle Correlation
                        |
                        v
[9] Verifier / Scorer Closure
                        |
              +---------+---------+
              |         |         |
            SOLVED   CANDIDATE    GAP
```

### 1.1 Safe Archive Ingest

`challenge_archive_ingest.js` 负责压缩包安全展开。目前自动处理 ZIP、TAR、GZIP/TGZ，以及 ZIP 容器类扩展名。展开时限制路径穿越、绝对路径、符号链接、加密 ZIP、异常压缩比、单文件大小、总展开大小、文件数量和递归深度。

RAR/7Z、ZIP64 等当前不能被确定性安全处理的输入不会偷偷调用系统解压程序，而是显式保留为 unsupported/GAP。

### 1.2 Workspace Evidence Scan

完整工作区进入 Finals Analyzer。这里先做静态识别，提取文件类型、源码结构、模型工件、数据集、网络端点、潜在 verifier、提示词/Agent 面、AI 模型安全面和其他确定性线索。

核心原则是先收集证据，再决定分析器，不以文件名或题名直接推答案。

### 1.3 Recovered Artifact Fixed Point

Base64、嵌套容器、递归解码等模块恢复出的完整工件会落盘到 `__recovered__`，随后重新扫描。当前最多进行受限的固定点复扫，避免“恢复出了真正附件，但后面的专业分析器看不到它”的断链问题。

每个恢复工件保留 SHA-256 与来源信息，并做去重与尺寸限制。

### 1.4 AI Preprocessing Evidence

`ai_preprocessing_manifest.js` 从源码中恢复模型输入预处理证据，例如：

- `Resize` / `cv2.resize`
- `CenterCrop` / `RandomCrop`
- RGB/BGR/灰度转换
- `ToTensor`、NCHW、`permute`
- `/255`、`[-1,1]`
- Normalize mean/std
- dtype、batch 维度与输入 shape

只有证据完整且不存在冲突时才进入 `executionReady`。NewCyber 不会因为看到 ResNet、ImageNet 或 ONNX 就擅自补 ImageNet 默认 mean/std。

### 1.5 Training Family Match

统一 training curriculum 汇总公开赛题的“题型结构、证据模式、分析策略与 provenance”。Challenge Session 会把当前附件证据映射到已经训练过的赛题 family，用于选择更合适的下一步分析策略。

匹配依据包含 findings、文件类型、模型/数据工件、preprocessing、ONNX/verifier 等证据，不只看题名。

当前训练覆盖包括：

- Prompt Injection / System Prompt / RAG / Agent trust boundary
- Adversarial Example / ONNX logits ranking
- Model Extraction
- Privacy Leakage / Model Inversion
- Backdoor / Poisoning
- AI Supply Chain / unsafe model artifact
- Dataset Pipeline Security
- OCR / Audio / Multimodal families
- 国内公开 AI 检测型靶场：对抗检测、loss-history 投毒检测、Xception 深伪检测

训练集只保存 challenge-derived metadata 与 synthetic fixture。公开赛题的真实 Flag、密钥、session secret、真实答案和 winning payload 不进入训练 fixture。

### 1.6 Local ONNX / Prepared Tensor

对于证据充分的 ONNX 题，NewCyber 可以在本地受控 runtime 中检查模型并运行推理。

已支持：

- 数值型 `.npy` -> tensor feed
- shape 精确匹配或证据安全的 batch=1 补维
- 显式 JSON tensor feed bundle
- 证据完备的图像 preprocessing 路径
- 单输入 ONNX 自动候选批量推理
- 完整输出向量检查后再交给赛式 ranker

不会自动反序列化 `.pt/.pth/.pkl`，也不会执行题目自带 Python 来“方便加载模型”。

### 1.7 Contest Bundle Correlation

`ai_contest_bundle_autopilot.js` 会把分散在不同文件里的 hints、logits、score table、candidate rows 与 verifier 信息关联起来。

支持 JSON、JSONL、CSV/TSV 以及部分 Python-like 静态 hint 结构。对于对抗样本型赛题，可进一步进入 target/origin、Top1/Top2、margin、runner-up 等 ranking 逻辑。

### 1.8 Verifier / Scorer Closure

NewCyber 区分“找到候选”和“题目已经验证”。

- `SOLVED`：存在题目 verifier、digest、明确 checker 或其他强验证证据闭环。
- `CANDIDATE`：确定性分析给出候选，但尚无题目级验证。
- `GAP`：缺少必要输入、模型运行条件、preprocessing 证据、ground truth、远程交互信息等。

没有 verifier 时，不会因为 heuristic 分数很高就自动升级成 solved。

## 2. Batch75：国内 AI 检测型赛题能力

Batch75 引入三类公开赛题衍生能力：

### 对抗图像检测

family：`image-adversarial-detection-scoring`

新增独立 scorer，可从已有 truth/prediction 或 truth/score+threshold 重新计算：

- TP / TN / FP / FN
- Accuracy
- Precision / Recall
- Specificity
- F1
- Balanced Accuracy

目的是不盲信题目脚本打印出的最终 accuracy，而是让 NewCyber 自己复算结果。

### 投毒样本检测

family：`loss-history-poison-ranking`

针对“按每个样本的 loss 历史变化进行异常排序”的赛式结构，提供透明可复算的 synthetic evaluator。当前训练指标使用相邻 loss 的 mean absolute change / RMS change / net change 进行候选排序。

这只是从公开题面抽象出的训练策略，不声称复刻原题隐藏实现；真实附件仍必须重新从当前数据取证和调参。

### DeepFake 检测

family：`xception-deepfake-detection`

用于识别 Xception / DeepFake / FaceForensics 一类检测 pipeline，并把最终逐文件 real/fake 输出重新接入统一二分类 scorer。

## 3. 安全边界

Drop-to-Result 的自动化不是“拿到附件什么都执行”。以下边界默认保持：

1. 不运行赛题自带任意 Python / Shell / Node 脚本。
2. 不自动 `torch.load`、pickle load 或加载来源未知的 `.pt/.pth/.pkl`。
3. 不从模型名猜预处理参数。
4. 多模型、多输入或证据冲突时优先 GAP，不随机选择。
5. 不把 heuristic/candidate 当 verifier-backed solved。
6. 不把历史赛题答案迁移到当前题目。
7. 不因为训练 family 相似就认为两题答案结构相同。
8. 默认不擅自访问附件中出现的远程服务；需要远程上下文时由 Challenge Session 明确列出缺失信息。

## 4. 自动化产物

Challenge Session 在适用时会产生或暴露以下结果：

```text
newcyber_ingest_manifest.json
newcyber_recovered_manifest.json
newcyber_onnx_autopilot.json
newcyber_training_family_match.json
```

UI 的 `DROP-TO-RESULT PIPELINE` 会展示 Archive、Recover、Preprocess、ONNX、Verify 等阶段的 DONE / PARTIAL / GAP / IDLE / SKIP 状态。

## 5. 下一阶段

接下来的重点不是继续无脑增加 corpus 数量，而是提高“训练资产 -> 当前附件自动动作”的转化率：

- 自动识别检测题 CSV/JSON/JSONL 的 truth/prediction/score 列，并直接运行 scorer。
- 自动识别 loss-history 表和序列，直接生成投毒候选排名。
- 把 training family match 转换成有输入契约的 strategy plan；满足契约的步骤自动运行，不满足的步骤输出缺失证据。
- 继续增强图像 preprocessing 的确定性执行覆盖。
- 对多模型/多数据集 Bundle 增加基于源码引用关系的配对，而不是按文件名猜。
- 把最终输出统一收敛成 `solved / candidate / needs-input / gap`，并给出具体证据链。

最终目标保持不变：**用户只负责把题目附件丢进来；NewCyber 尽可能自己把能确定的步骤全部做完，并对做不了的部分明确说明缺什么。**
