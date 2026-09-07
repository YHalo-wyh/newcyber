# NewCyber

NewCyber 是为线下断网安全竞赛准备的多方向本地工具箱，当前重点服务第二届湾区杯决赛的四个方向：

- 车联网安全
- 低空经济安全
- 人工智能安全
- 区块链安全

四个方向彼此独立，共用 Electron 外壳和少量通用能力。项目目标不是“一键解题”，而是把比赛中重复、耗时、容易忘的步骤做成确定性离线工具。

## 当前可用工具

### 车联网

- CAN/candump 文本分析：CAN ID、帧数、DLC、平均周期、变化字节、递增 counter 候选
- UDS / ISO-TP 快速解码：常见 Service、NRC、SecurityAccess、DID、Single/First Frame

### 低空经济

- MAVLink v1/v2 原始十六进制流结构解析
- 常见 MAVLink MSGID 识别（HEARTBEAT、GPS、ATTITUDE、COMMAND_LONG 等）
- NMEA RMC / GGA 解析：经纬度、速度、高度、卫星数、轨迹范围与累计距离

### 人工智能安全

- AI Pipeline 源码快速审计
- 检查 `torch.load` / pickle、Shell sink、`eval/exec`、动态 Prompt、RAG、Agent/Tool 调用面、硬编码凭据
- 保留原有 NumPy / SafeTensors / PyTorch ZIP 安全结构检查，不直接反序列化不可信模型

### 区块链安全

- EVM calldata 拆分，识别常见 ERC-20 selector
- 32-byte word 的 uint256 / address 候选展示
- EVM bytecode 离线反汇编
- 标记 CALL / DELEGATECALL / ORIGIN / SELFDESTRUCT / CREATE2 等高价值 opcode

### 通用

- Text/Hex/Base64/URL 转换
- SHA-256 / MD5
- 循环 Hex XOR
- 离线知识速查（UDS、MAVLink、AI、EVM）
- 赛题目录只读扫描：文件类型、字符串、Flag/URL/IP 候选、WAV/PCAP/模型基础检查
- Markdown 报告导出

## 运行

```powershell
npm install
npm start
```

也可以在 Windows 双击 `启动 NewCyber.cmd`。

## 测试

```powershell
npm test
```

## 设计原则

1. **Offline-first**：核心工具不依赖网络。
2. **Deterministic-first**：能用解析器、规则和明确算法完成的，不交给大模型猜。
3. **赛道隔离**：车联网、低空、AI、区块链的工具和题目上下文不混在一起。
4. **不执行不可信附件**：默认只读；模型文件不直接 `pickle.load` / `torch.load`。
5. **辅助解题，不伪装成自动解题**：启发式结果必须人工确认。

## 代码结构

```text
main.js                     Electron 主进程与 IPC
preload.js                  渲染层白名单接口
src/core/analyzer.js        原有赛题目录只读扫描器
src/core/formats.js         WAV / PCAP / 模型等格式分析
src/core/toolbox.js         四方向离线工具核心
renderer/toolbox.html       多方向工具箱入口
renderer/toolbox.js         多方向工具箱 UI
renderer/styles/toolbox.css 界面样式
tests/toolbox.test.js       工具箱回归测试
```

## 下一批优先扩展

- 车联网：ISO-TP 多帧重组、UDS TransferData 固件恢复、MQTT、DBC/ASC
- 低空：MAVLink CRC/dialect、TLOG、PX4 ULog、ArduPilot DataFlash、GNSS 异常检测
- AI：数据集统计/投毒线索、RAG 数据库、pickle opcode、ONNX/GGUF 深度检查
- 区块链：ABI 类型化解码、Solidity 静态规则、Foundry/Anvil/Slither 本地联动、Solana 最小支持
- 通用：更完整的离线知识库和环境自检
