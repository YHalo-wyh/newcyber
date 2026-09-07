# NewCyber

NewCyber 是为线下断网安全竞赛准备的多方向本地工具箱，当前重点服务第二届湾区杯决赛及国内同类赛事的四个方向：

- 车联网安全
- 低空经济安全
- 人工智能安全
- 区块链安全

四个方向彼此独立，共用 Electron 外壳和少量通用能力。项目目标不是“一键解题”，而是把比赛中重复、耗时、容易忘的步骤做成确定性离线工具，并用公开真题持续校验规则是否真正泛化。

## 当前可用工具

### 车联网

- CAN/candump 分析：CAN ID、帧数、DLC、平均周期、变化字节、状态跃迁、递增 counter 候选
- PCAPNG / SocketCAN 只读解析，保留原始包与 CAN 帧映射
- CANopen SDO：对象字典索引、读写请求、expedited / segmented transfer、toggle 与字符串重组
- ISO-TP 多帧重组
- UDS 解码：Session、SecurityAccess、DID、ReadMemoryByAddress、TransferData 等常见服务
- UDS 刷写重组：`0x34 RequestDownload → 0x36 TransferData → 0x37 RequestTransferExit`，校验 blockSequenceCounter、声明长度并输出 block map
- UDS 二进制产物：仅在无 gap / 冲突且长度一致时生成 SHA-256 绑定的 firmware / raw-transfer artifact，可直接保存继续逆向

### 低空经济

- MAVLink v1/v2 原始十六进制流结构解析
- 常见消息深度解析：HEARTBEAT、COMMAND_LONG、SERIAL_CONTROL、STATUSTEXT、FILE_TRANSFER_PROTOCOL 等
- 飞控安全事件：ARM/DISARM、`ARM → SERIAL_CONTROL`、sequence gap、未签名 MAVLink2
- MAVLink2 signing trailer：Link ID、48-bit timestamp、48-bit signature、timestamp rollback 线索
- MAVLink2 签名离线验证：输入 32-byte key + signed frame，重算 SHA-256/48 并比较 wire signature
- MAVLink FTP：session、opcode、request opcode、offset、path/data/error 拆解
- MAVLink FTP 文件重组：按 remote/session/offset 聚合 ReadFile/BurstReadFile ACK，识别重传、冲突、gap 与 EOF，并只对完整覆盖生成可保存文件 artifact
- ArduPilot AP_Param EEPROM / StorageKeys：固定结构定位、32-byte signing key 提取与哈希
- NMEA RMC / GGA：经纬度、速度、高度、卫星数、轨迹范围与累计距离

### 人工智能安全

- AI Pipeline 源码快速审计：不可信输入 / Prompt / 模型输出到 Tool、Shell、文件、网络和 Crypto sink
- LLM → Crypto 链：模型输出参与 Hash/KDF/加密以及可重放生成参数
- AI / ASR → Shell：覆盖直接插值和一跳中间变量传播
- 目标输出型生成题：提取 `from_pretrained()` 模型、generation 参数、目标字符串 oracle、输入长度限制并识别确定性 greedy generation
- 结构化模型数据画像（CSV/TSV）：分位数、均值/标准差、强相关特征、中心样本索引、NaN/Inf 边界
- 表格模型候选验证：计算 RMS standardized distance、Q05-Q95 主体区间和强相关条件残差，只评估 profile compatibility，不冒充真实模型 anomaly score
- 高维表格数据自动进入 workspace AI 证据，用于 Isolation Forest / XGBoost / 风控模型题的第一轮离线分析
- NumPy / SafeTensors / PyTorch ZIP 安全结构检查，不直接反序列化不可信模型

### 区块链安全

- EVM calldata 拆分，识别常见 ERC-20 selector
- 32-byte word 的 uint256 / address 候选展示
- EVM runtime bytecode 离线反汇编
- runtime dispatcher 恢复：`PUSH4 → EQ → JUMPI` selector 与 jump destination
- EVM storage/state 证据：SLOAD/SSTORE、直接 slot 与同 basic block 低/中置信候选；不冒充完整符号执行
- EVM 局部数据流：在单 basic block 内追踪 `CALLDATALOAD → MSTORE/CALLDATACOPY → SLOAD/SSTORE/CALL`，展示 CALL target/value/input 来源，跨 CFG 边界保持 unknown
- Solidity 静态规则：tx.origin、delegatecall、低级 call、初始化、ABI smuggling 等
- Solana / Anchor：Program ID、instruction、PDA seeds、Signer/AccountInfo、Anchor.toml、链上日志线索

### 通用

- Text/Hex/Base64/URL 转换
- SHA-256 / MD5
- 循环 Hex XOR
- 离线知识速查（UDS、MAVLink、AI、EVM）
- 赛题目录只读扫描：文件类型、字符串、Flag/URL/IP 候选、WAV/PCAP/模型基础检查
- Markdown 报告导出
- 二进制 artifact 导出：主进程保存前重新校验 hex 长度、size、SHA-256 与 completeness，renderer 不直接写文件

## 真题回归 / Corpus

当前 CI 持续使用公开固定版本的真题或附件做回归，包括：

- CISCN Finals：CAN / MQTT 等公开附件
- UDSCTF：ISO-TP / UDS SecurityAccess / ReadMemory 等
- USTC Hackergame 2023《小型大语言模型星球》：目标输出型生成题
- SUCTF：SU_easyLLM、Onchain_Checkin、Onchain_Magician
- LilCTF 2025《生蚝的宝藏》：真实 EVM runtime selector / storage 证据
- STARPWN 2026 One to Rule Them All：ArduPilot EEPROM / MAVLink2 signing key
- 湾区杯等公开附件 corpus

真题只用于暴露能力缺口与锁定泛化行为；核心规则不写题名特判。

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
6. **Real-corpus driven**：真题推动通用能力，回归锁行为，不为题名写特殊分支。
7. **Artifact must be provable**：可保存产物必须绑定 size / SHA-256 / provenance；有 gap 或冲突就保留证据，不伪造完整文件。

## 代码结构

```text
main.js                              Electron 主进程、IPC 与 artifact 保存校验
preload.js                           渲染层白名单接口
src/core/artifacts.js                统一二进制 artifact 格式与 SHA-256 校验
src/core/finals_analyzer.js          四赛道 workspace 专项分析入口
src/core/vehicle*.js                 CAN / CANopen / ISO-TP / UDS / 刷写恢复
src/core/uds_programming.js          UDS block map / firmware artifact
src/core/low_altitude*.js            ArduPilot / MAVLink / signing / FTP
src/core/mavlink_ftp_reassembly.js   MAVLink FTP 文件块重组与 artifact
src/core/ai_source.js                AI 源码与生成链审计
src/core/ai_tabular.js               表格模型数据画像与候选验证
src/core/evm_runtime.js              EVM runtime / dispatcher / storage / 局部 data flow
src/core/solana.js                   Solana / Anchor 审计
renderer/batch3_tools.js             Artifact pipeline / AI candidate / EVM data-flow UI
renderer/artifact_tools.js           统一 artifact 保存动作
renderer/*_tools.js                  各赛道独立 UI 扩展
.github/workflows/corpus-smoke.yml   公开真题 corpus gate
```

## 下一批优先扩展

- 车联网：UDS `dataFormatIdentifier` / 厂商自定义压缩与加密头识别、MQTT 车机协议证据
- 低空：MAVLink CRC extra / dialect、TLOG、PX4 ULog / ArduPilot DataFlash
- AI：树模型 / Isolation Forest 模型文件结构证据、ONNX/GGUF 深度检查、RAG 向量库离线审计
- 区块链：proxy / implementation 恢复、跨 basic-block CFG evidence、DeFi 资产流摘要
- 通用：artifact 证据包（binary + provenance + report）统一导出、环境自检
