# NewCyber

NewCyber 是面向 CTF、AI 安全专项赛和攻防修复题的本地分析工作台。第一版聚焦赛题接收后的快速分诊：固定证据、识别题型、提取关键线索，并生成可复核、可交接的分析报告。

## 当前能力

- 递归盘点赛题附件，计算 SHA-256、文件类型、大小与字节熵
- 按附件和代码特征判断 AI/ML、取证、逆向、Web、密码、Pwn、恶意样本等方向
- 从文本与二进制可打印字符串中提取 Flag、URL、IP 地址候选
- 发现命令拼接、不可信反序列化、硬编码凭据、SQL 拼接等待验证线索
- 识别 WAV、PCAP/PCAPNG、PE、ELF、APK/JAR、SQLite、PDF 等格式
- 文件预览、队伍记录、Markdown 报告导出

NewCyber 默认只读分析附件，不执行赛题程序，也不直接加载 `.pt`、`.pth`、`.pkl` 等可能触发反序列化的模型文件。

## 运行

```powershell
cd electron-app
npm install
npm start
```

## 测试

```powershell
npm test
```

## 结构

```text
main.js                     Electron 主进程与受控文件对话框
preload.js                  渲染层白名单接口
src/core/analyzer.js        只读扫描、分类、线索提取与报告生成
renderer/index.html         页面入口
renderer/app.js             工作台交互
renderer/styles/theme.css   界面样式
```

## 使用流程

1. 点击“选择赛题目录”。
2. 查看总览中的题型判断和建议路线。
3. 在“文件证据”中核对关键附件和哈希。
4. 在“分析发现”和“候选结果”中验证线索来源。
5. 把已确认事实与失败尝试记入“队伍记录”，导出报告交接。

## 当前边界

这是通解工具的基础层，不替代 IDA、Wireshark、Volatility、模型评测框架等专用工具。后续适配器会在隔离环境中调用这些工具，并把结果回收到同一证据模型中。
