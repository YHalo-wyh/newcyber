# Batch44 · i春秋 AI 赛题训练回归

本批次继续围绕初赛五方向中的 **提示词工程与大模型安全** 做针对性训练，不把公开 WP 当作“答案库”，而是抽取可复用的攻击家族、显式失败证据和负样本控制。

## 公开来源

### 2025 春秋杯网络安全联赛冬季赛

官方赛事页：

- https://www.ichunqiu.com/competition/detail/378

公开题解交叉来源：

- https://www.cnblogs.com/xvzhang/articles/19885405
- https://blog.x-z-z.com/article/2026-02-14-02-17.html

本批次只登记公开题面能够确认的 AI 题型：

| 题目 | 训练家族 | NewCyber 训练目标 |
| --- | --- | --- |
| 越狱的翻译官 | task-wrapper-secret-exfiltration | 识别“仍然执行翻译/改写任务，但把隐藏上下文当作处理对象”的泄露 |
| 健忘的客服 | multi-turn-auth-context-exfiltration | 识别规则刺探、伪授权语义与隐藏历史泄露的多轮链 |
| 窥探内心 | persona-system-secret-exfiltration | 区分人格/角色扮演与真实消息权限，检测系统标识外泄 |
| 幻觉诱导 | false-premise-hallucination | 使用结构化 ground truth + judge 结果验证错误事实是否被接受，不靠关键词猜幻觉 |

真实 Flag 不进入训练 corpus。所有秘密泄露样本都替换为 `TRAINING_CANARY_9F3A`，所有越权服从样本使用训练 marker；“幻觉诱导”只回放结构化 judge 证据。

### 2024 巅峰极客挑战赛

官方 i春秋页面可以确认存在独立的“大模型安全检测环节”：

- https://www.ichunqiu.com/competition/detail/341

由于目前没有足够公开的具体题目附件/判题细节，本批次只把它登记为 **competition-format-signal**，不凭空生成题目样本。这条约束写进 corpus，防止后续为了“数量”污染训练集。

## 新增工具路由

- `ai-ichunqiu-training-corpus`：返回公开来源、题型家族和训练能力描述。
- `ai-ichunqiu-training-regression`：执行 4 道题、12 个变体的回归，包含攻击证据与负样本控制。
- `ai-false-premise-replay`：对已知 `groundTruth` / `judgeAccepted` 的错误前提回放进行解释；没有判题证据时不下结论。

## 为什么这样训练

之前的通用 Prompt Injection 模板已经覆盖 direct override、role smuggling、RAG、tool output、hidden context 等大类，但国内比赛里经常把攻击藏在“业务任务外壳”中：翻译、客服、人格、历史知识问答。只用一句 `ignore previous instructions` 做回归会过拟合模板，不代表比赛里真能认出来。

所以 Batch44 增加两层约束：

1. **比赛语义层**：先识别题目到底是在测隐藏上下文、伪授权、多轮状态，还是错误事实诱导。
2. **证据层**：秘密泄露用 canary、越权执行用 marker/tool-call、幻觉用 judge oracle；没有明确证据就保持 `no-explicit-failure`。

目标仍然是让 NewCyber 在拿到题目后更快判断“这是哪类 AI 安全题、应该验证什么、当前证据够不够”，而不是把随机自然语言输出冒充成已解题。
