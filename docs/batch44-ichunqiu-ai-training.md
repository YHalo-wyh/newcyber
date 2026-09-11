# Batch44 · i春秋 AI 赛题训练回归

本批次继续围绕初赛五方向中的 **提示词工程与大模型安全** 做针对性训练，不把公开 WP 当作“答案库”，而是抽取可复用的攻击家族、显式失败证据和负样本控制。

## 公开来源

### 2025 春秋杯网络安全联赛冬季赛

官方赛事页：

- https://www.ichunqiu.com/competition/detail/378

赛事官方报道：

- https://www.integritytech.com.cn/html/News/News_836_1.html

官方报道明确把本届 AI 大模型安全题的风险面概括为四类：**提示词注入、敏感信息泄露、系统提示泄露、错误信息暴露**。Batch44 将这四类风险作为训练覆盖基线，而不是用“收集了多少条 Prompt”衡量完整度。

公开题解交叉来源：

- https://www.cnblogs.com/xvzhang/articles/19885405
- https://blog.x-z-z.com/article/2026-02-14-02-17.html

本批次只登记公开题面能够确认的 AI 题型：

| 题目 | 训练家族 | 官方风险映射 | NewCyber 训练目标 |
| --- | --- | --- | --- |
| 越狱的翻译官 | task-wrapper-secret-exfiltration | 提示词注入、系统提示泄露 | 识别“仍然执行翻译/改写任务，但把隐藏上下文当作处理对象”的泄露 |
| 健忘的客服 | multi-turn-auth-context-exfiltration | 提示词注入、敏感信息泄露、系统提示泄露 | 识别规则刺探、伪授权语义与隐藏历史泄露的多轮链 |
| 窥探内心 | persona-system-secret-exfiltration | 提示词注入、系统提示泄露 | 区分人格/角色扮演与真实消息权限，检测系统标识外泄 |
| 幻觉诱导 | false-premise-hallucination | 错误信息暴露 | 使用结构化 ground truth + judge 结果验证错误事实是否被接受，不靠关键词猜幻觉 |

当前 challenge-derived corpus 对官方四类风险的映射覆盖为 **4/4**。这只是题型/证据覆盖，不代表某个真实大模型已经通过安全测试，更不代表 NewCyber 能自动解出所有同类赛题。

真实 Flag 不进入训练 corpus。所有秘密泄露样本都替换为 `TRAINING_CANARY_9F3A`，所有越权服从样本使用训练 marker；“幻觉诱导”只回放结构化 judge 证据。

### 2024 巅峰极客挑战赛

官方 i春秋页面可以确认存在独立的“大模型安全检测环节”：

- https://www.ichunqiu.com/competition/detail/341

由于目前没有足够公开的具体题目附件/判题细节，本批次只把它登记为 **competition-format-signal**，不凭空生成题目样本。这条约束写进 corpus，防止后续为了“数量”污染训练集。

另外检索了 2024/2025 春秋杯夏季赛、2024 春秋杯冬季赛等公开页面；在没有找到足够明确的 AI 题目附件、题面或可交叉验证 WP 时，暂不加入训练语料。宁可缺一条，也不让“可能是 AI 题”变成伪真题。

## 新增工具路由

- `ai-ichunqiu-training-corpus`：返回公开来源、题型家族、官方风险标签和训练能力描述。
- `ai-ichunqiu-training-regression`：执行 4 道题、12 个变体的回归，包含攻击证据、负样本控制以及官方风险覆盖统计。
- `ai-false-premise-replay`：对已知 `groundTruth` / `judgeAccepted` 的错误前提回放进行解释；没有判题证据时不下结论。

## 为什么这样训练

之前的通用 Prompt Injection 模板已经覆盖 direct override、role smuggling、RAG、tool output、hidden context 等大类，但国内比赛里经常把攻击藏在“业务任务外壳”中：翻译、客服、人格、历史知识问答。只用一句 `ignore previous instructions` 做回归会过拟合模板，不代表比赛里真能认出来。

所以 Batch44 增加三层约束：

1. **官方风险层**：以赛事公开定义的四类大模型风险做 coverage gate，避免训练方向跑偏。
2. **比赛语义层**：先识别题目到底是在测隐藏上下文、伪授权、多轮状态，还是错误事实诱导。
3. **证据层**：秘密泄露用 canary、越权执行用 marker/tool-call、幻觉用 judge oracle；没有明确证据就保持 `no-explicit-failure`。

目标仍然是让 NewCyber 在拿到题目后更快判断“这是哪类 AI 安全题、应该验证什么、当前证据够不够”，而不是把随机自然语言输出冒充成已解题。
