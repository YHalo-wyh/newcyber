# NewCyber

NewCyber 是面向安全竞赛的多方向分析工作台，当前重点覆盖国内同类赛事中的四个方向：

- 车联网安全
- 低空经济安全
- 人工智能安全
- 区块链安全

项目默认使用 **比赛模式**：拿到题目后优先选择整个赛题目录，让工具先判断方向、找 Flag 候选、恢复可继续利用的文件/固件，并把下一步压缩成 1～3 个动作。复杂协议字段、模型结构和 EVM 证据默认折叠，需要复核时再展开。

目标不是“一键解题”，而是把比赛中重复、耗时、容易遗漏的分析步骤做成确定性工具，让只掌握基础原理的使用者也能顺着证据继续推进。

## 比赛模式

1. 选择赛题目录。
2. NewCyber 扫描附件并判断更像车联网、低空、AI 还是区块链。
3. Flag 候选、高危线索、完整 firmware / FTP 文件 / 自动解码文件优先置顶。
4. 页面只给最多 3 个下一步动作，例如“验证 Flag”“导出固件去 IDA”“先分析 implementation”。
5. 卡住时再展开技术细节。

如果分析途中拿到一段可疑字符串，可以直接点 **“试解可疑结果”**；选中了文本就试选中的内容，否则工具会从当前结果里寻找明显像 Hex/Base64/转义/bit/字节列表的数据并继续自动试解。

### 快捷操作

- `Ctrl + K`：打开全局命令面板，直接跳赛道、页面或具体工具。
- `Ctrl + Enter`：在任意工具输入页直接运行当前分析。
- `Ctrl + Shift + O`：直接选择赛题目录并开始扫描。
- 左上角侧栏按钮：折叠/展开导航；桌面端状态会保存在本机 `localStorage`。
- 工具输入区实时显示字符数和行数，长日志/源码输入时不用再额外估算规模。

这些交互只在渲染层工作，不增加网络请求，也不改变底层分析结果。

## 当前可用工具

### 车联网

- CAN/candump 分析：CAN ID、帧数、DLC、平均周期、变化字节、状态跃迁、递增 counter 候选
- PCAPNG / SocketCAN 解析，保留原始包与 CAN 帧映射
- CANopen SDO：对象字典索引、读写请求、expedited / segmented transfer、toggle 与字符串重组
- ISO-TP 多帧重组
- UDS 解码：Session、SecurityAccess、DID、ReadMemoryByAddress、TransferData 等常见服务
- UDS 刷写重组：`0x34 RequestDownload → 0x36 TransferData → 0x37 RequestTransferExit`，校验 blockSequenceCounter、声明长度并输出 block map
- UDS 二进制产物：仅在无 gap / 冲突且长度一致时生成 SHA-256 绑定的 firmware / raw-transfer artifact，可直接保存继续逆向

### 低空经济

低空板块按 **信息侦查 / 协议欺骗 / 拒绝服务 / 注入攻击 / 信息泄露 / 固件攻击** 六类攻击面组织，不再把题型拆成大量孤立按钮。

- **信息侦查**：Wi-Fi/SSID/BSSID/认证方式、端口与服务 banner、PCAP/PCAPNG 嗅探、设备/飞控/RTSP 指纹、消息频率与序列基线
- **协议欺骗**：姿态、GPS、卫星、VFR_HUD、SYS_STATUS、电池和错误/紧急状态候选；MAVLink telemetry payload 会进入跨消息物理一致性检查
- **遥测一致性**：解析 `GPS_RAW_INT / GLOBAL_POSITION_INT / ATTITUDE / SYS_STATUS / VFR_HUD`，检查位置跳变隐含速度、GPS 双源差异、姿态跳变与角速度、电池范围、sensor-health、VFR 地速/高度矛盾
- **拒绝服务与状态阻断**：围栏参数变更、Deauth/Disassociation 日志、GPS offset、flight termination、视频中断、PreArm/阻止起飞、链路洪水等证据归因
- **控制注入状态机**：解析 `SET_MODE / PARAM_SET / PARAM_VALUE / MISSION_COUNT / MISSION_ITEM / MISSION_ITEM_INT / COMMAND_LONG / COMMAND_ACK`，恢复发送方、参数写入、任务航点、命令与 ACK
- **高风险控制语义**：地理围栏、failsafe/arming、飞行模式、DO_SET_HOME、DO_FLIGHTTERMINATION、相机/云台、航点上传、多控制源竞争
- **信息泄露与取证**：飞行日志、参数、Wi-Fi 客户端、FTP、RTSP/RTP/H264/H265 线索；MAVLink FTP 按 remote/session/offset 重组文件
- **MAVLink v1/v2**：帧结构、sequence、常见消息、CRC X.25 + CRC_EXTRA、MAVLink2 signing trailer、linkId、48-bit timestamp、signature rollback
- **MAVLink2 签名验证**：输入 32-byte key + signed frame 重算 SHA-256/48；ArduPilot EEPROM / StorageKeys 可恢复 signing key 候选
- **固件结构分析 / 解包**：识别 TP-Link v1/v2 厂商头、U-Boot uImage、SquashFS、JFFS2、UBI、CramFS、gzip、XZ、ELF、DTB、ZIP 等 magic
- **固件 segment 恢复**：对有可靠 offset/length 的 kernel/rootfs/bootloader、uImage、SquashFS、gzip 解码结果生成带 SHA-256/provenance 的 artifact；大型段保留结构证据并交给 extractor
- **固件 extractor backend**：可从工作台调用本机 `binwalk -eM`；SquashFS/JFFS2/UBI 分别给出 `unsquashfs / jefferson / ubireader_extract_files` 路线
- **赛题题型矩阵**：覆盖 Wi-Fi 破解、端口侦查、数据嗅探、姿态/GPS/电池/状态欺骗、Deauth/GPS offset/终止飞行/阻止起飞、GCS/MAVLink/航点/传感器/云台/机载主机注入、日志/参数/FTP/摄像机泄露和固件攻击面

### 人工智能安全

- AI Pipeline 源码快速审计：不可信输入 / Prompt / 模型输出到 Tool、Shell、文件、网络和 Crypto sink
- LLM → Crypto 链：模型输出参与 Hash/KDF/加密以及可重放生成参数
- AI / ASR → Shell：覆盖直接插值和一跳中间变量传播
- 目标输出型生成题：提取 `from_pretrained()` 模型、generation 参数、目标字符串 oracle、输入长度限制并识别确定性 greedy generation
- 结构化模型数据画像（CSV/TSV）：分位数、均值/标准差、强相关特征、中心样本索引、NaN/Inf 边界
- 表格模型候选验证：计算 RMS standardized distance、Q05-Q95 主体区间和强相关条件残差，只评估 profile compatibility，不冒充真实模型 anomaly score
- 高维表格数据自动进入 workspace AI 证据，用于 Isolation Forest / XGBoost / 风控模型题的第一轮分析
- SafeTensors 深度结构审计：校验 dtype、shape、`data_offsets`、实际 byte range、越界、overlap 与长度一致性
- NumPy NPY 深度审计：解析 descr/shape/fortran_order，校验固定 dtype payload 长度，并把 object dtype / pickle 语义显式标高风险
- PyTorch ZIP 深度审计：沿用 storage/参数/训练日志证据，并静态解析 `data.pkl` pickle opcode / GLOBAL / STACK_GLOBAL；高风险 global 与普通 `torch.*` 引用分级，不执行 `torch.load` / `pickle.loads`
- **对抗样本候选验证**：对 original/adversarial 成对样本计算 L0/L1/L2/L∞、epsilon budget、clip 越界、targeted/untargeted outcome；只验证候选是否满足已知约束，不猜模型输出
- **对抗测试 harness**：为 ART / Foolbox 生成本地模板，模型 wrapper 与 preprocessing 必须按赛题可信代码补齐
- **Membership Inference transcript 审计**：对 confidence/loss/entropy 计算成员/非成员 AUC、最佳阈值与 balanced accuracy；无 ground truth 时明确保持不可验证
- **隐私测试 harness**：生成 Privacy Meter / ART 对接模板，NewCyber 负责 transcript 归一化与结果解释
- **数据投毒 / 后门候选**：检测重复样本、同特征冲突标签、极低频标签、低支持度高标签绑定 token，并要求通过 trigger 删除/替换继续验证
- **数据质量 / 后门 harness**：生成 cleanlab / BackdoorBench 对接路线，不把统计共现直接判定成真实后门
- **AI 供应链审计**：检查 `trust_remote_code=True`、未固定 Hugging Face revision、运行期 pip、动态 `sys.path`、pickle/joblib/torch 可执行语义加载、自定义 index / VCS / URL 依赖
- **模型安全交叉证据**：内置静态模型审计可与 ModelScan / PickleScan 的 CLI 结果合并；任何单一扫描器的 clean 都不会被解释为“模型可安全执行”

### 区块链安全

- EVM calldata 拆分，识别常见 ERC-20 selector
- 32-byte word 的 uint256 / address 候选展示
- EVM runtime bytecode 反汇编
- runtime dispatcher 恢复：`PUSH4 → EQ → JUMPI` selector 与 jump destination
- EVM storage/state 证据：SLOAD/SSTORE、直接 slot 与同 basic block 低/中置信候选；不冒充完整符号执行
- EVM 局部数据流：在单 basic block 内追踪 `CALLDATALOAD → MSTORE/CALLDATACOPY → SLOAD/SSTORE/CALL`，展示 CALL target/value/input 来源，跨 CFG 边界保持 unknown
- EIP-1167 minimal proxy：只在 canonical runtime 完整匹配时恢复内嵌 implementation 地址
- EIP-1967 proxy evidence：识别 implementation/admin/beacon 标准 storage slot，并把 slot 的 SLOAD/SSTORE 与 DELEGATECALL / upgrade selector 证据关联；只有 implementation slot 真正流入 DELEGATECALL 才给高置信
- Solidity 静态规则：tx.origin、delegatecall、低级 call、初始化、ABI smuggling 等
- Caller-controlled external contract trust：追踪函数参数或 calldata struct 中的外部接口对象，检查其返回值是否进入资产/价格/权限语义，并识别 allowlist/registry/codehash 等来源约束
- `abi.encodePacked` 多动态参数 collision 证据与链属性弱随机证据
- Solana / Anchor：Program ID、instruction、PDA seeds、Signer/AccountInfo、Anchor.toml、链上日志线索

### 通用 / 自动试解

- Text/Hex/Base64/URL 转换
- SHA-256 / MD5
- 循环 Hex XOR
- **可疑数据自动试解**：Hex、Base64、Base64URL、Base32、Base58、URL、`\\xNN` / Unicode 转义、bit 串、十进制字节列表
- 自动继续尝试 Reverse、ROT13、Caesar、Atbash、单字节 XOR `0x01..0xff`、gzip、zlib；最多递归 3 层并按 Flag、文件头、可读性排序
- 结果自动识别 Flag，以及 PNG / ZIP / ELF / PDF / gzip / SQLite / JPEG / GIF / 7Z / RAR 等常见文件头
- 解出的完整二进制会生成 SHA-256 绑定 artifact，可直接导出继续解包、IDA/Ghidra 或取证
- **中间结果一键试解**：任何工具跑出可疑数据后可直接继续，不用手工搬运多轮编码
- **Workspace 轻量自动试解**：扫描小型文本附件中的明显编码串；解出的 Flag 直接进入比赛模式 Flag 候选，解出的文件进入“可继续利用的产物”
- 上下文强加密试解：从 Python/JS/TS/配置中提取 AES/SM4、mode、key、IV/nonce、tag、ciphertext；缺参数时保持 unknown
- 结构化赛题知识库：按赛道维护 trigger/evidence/prerequisite/verify/false-positive/action/mutation playbook
- 泛化样本生成：`generate-generalization-corpus.js` 与 `generate-uav-challenge-corpus.js` 生成语义保持的正例、负例和变异样本
- Markdown 报告导出
- 二进制 artifact 导出：主进程保存前重新校验 hex 长度、size、SHA-256 与 completeness

## 泛化训练 / Corpus

当前 CI 同时维护三类门禁：

- **真实公开题回归**：CISCN Finals、UDSCTF、SUCTF、LilCTF、STARPWN、Hackergame 等固定版本 corpus
- **Semantic Generalization**：随机化 identifier、CAN ID、SYSID/COMPID、编码方式、控制参数与负例，统计正例召回和负例正确拒绝；AI Batch 9 进一步按 capability family 分开计分，避免总分掩盖单个子能力退化
- **Holdout Challenge**：使用未针对题名编写规则的真实公开源码/附件验证能力族，例如 Paradigm CTF `token-locker` 的 external-contract trust boundary

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

1. **Beginner-first UI**：默认只展示方向、成果和下一步；底层证据折叠保留。
2. **Deterministic analysis pipeline**：协议、文件结构、密码和状态机优先使用可复核解析器与明确算法。
3. **赛道隔离**：车联网、低空、AI、区块链的工具和题目上下文不混在一起。
4. **不执行不可信附件**：模型、固件和赛题文件以静态解析为主；模型文件不直接 `pickle.load` / `torch.load`。
5. **辅助解题，不伪装成自动解题**：启发式结果必须人工确认；未知强加密不假装已经破解。
6. **Real-corpus driven**：真题推动通用能力，回归锁行为，不为题名写特殊分支。
7. **Semantic generalization gate**：正例换名/换参数后仍应命中，相似负例必须正确拒绝。
8. **Artifact must be provable**：可保存产物必须绑定 size / SHA-256 / provenance；有 gap 或冲突就保留证据，不伪造完整文件。
9. **UX 与分析核心解耦**：快捷键、命令面板和视觉状态放在独立 renderer enhancement 层，不能改变分析器输出或绕过证据门禁。

## 代码结构

```text
main.js                              Electron 主进程、IPC、固件选择/解包与 artifact 保存校验
preload.js                           渲染层白名单接口
src/core/artifacts.js                统一二进制 artifact 格式与 SHA-256 校验
src/core/auto_decode.js              多层自动解码 / 轻量密码尝试 / Flag 与文件头评分
src/core/finals_analyzer*.js         四赛道 workspace 专项分析与批次扩展
src/core/finals_analyzer_batch7.js   低空题型矩阵 / 固件 workspace enrichment
src/core/finals_analyzer_batch9.js   AI Batch 9 workspace enrichment
src/core/vehicle*.js                 CAN / CANopen / ISO-TP / UDS / 刷写恢复
src/core/uds_programming.js          UDS block map / firmware artifact
src/core/low_altitude*.js            ArduPilot / MAVLink / signing / FTP
src/core/uav_challenge_matrix*.js    低空六类攻击面与题型 Playbook 映射
src/core/uav_telemetry.js            GPS/姿态/SYS_STATUS/VFR_HUD 物理一致性
src/core/uav_control_flow.js         SET_MODE/PARAM/MISSION/COMMAND/ACK 控制状态机
src/core/firmware_unpack.js          固件 magic、厂商头、uImage/SquashFS/segment carve
src/core/mavlink_ftp_reassembly.js   MAVLink FTP 文件块重组与 artifact
src/core/mavlink_crc.js              MAVLink X.25 / common CRC_EXTRA 校验
src/core/ai_source.js                AI 源码与生成链审计
src/core/ai_source_batch9.js         AI Batch 9 source findings 汇总
src/core/ai_tabular.js               表格模型数据画像与候选验证
src/core/ai_adversarial.js           对抗样本预算/结果验证与 ART/Foolbox harness
src/core/ai_privacy.js               Membership Inference transcript/AUC/threshold
src/core/ai_dataset_security.js      数据冲突、trigger、投毒/后门候选与 harness
src/core/ai_supply_chain.js          模型/依赖/Hugging Face 供应链静态审计
src/core/ai_tooling.js               ModelScan/PickleScan 外部结果与内置证据合并
src/core/model.js                    PyTorch ZIP/storage/训练日志基础深审
src/core/model_artifacts.js          SafeTensors / NPY / pickle opcode-global 结构审计
src/core/evm_runtime*.js             EVM runtime / dispatcher / storage / 局部 data flow
src/core/evm_proxy.js                EIP-1167 / EIP-1967 proxy evidence
src/core/web3_general.js             external trust / packed dynamic / weak randomness
src/core/solana.js                   Solana / Anchor 审计
src/knowledge/*                      五类赛道结构化 Challenge Playbook
scripts/generate-generalization-corpus.js  四赛道/通用语义变异 corpus 生成
scripts/generate-uav-challenge-corpus.js   低空攻击面语义变异 corpus 生成
renderer/competition_mode.js         默认比赛模式：成果和下一步优先
renderer/uav_challenge_tools.js      低空六类分析器与固件工作台 UI
renderer/ai_batch9_tools.js          AI Batch 9 工具注册与结果 UI
renderer/auto_decode_tools.js        手动/中间结果一键自动试解 UI
renderer/artifact_tools.js           统一 artifact 保存动作
renderer/ux.js                       命令面板、快捷键、侧栏记忆、输入状态增强
renderer/styles/ux.css               独立 UX/视觉覆盖层，不侵入分析核心
.github/workflows/corpus-smoke.yml   公开真题 corpus gate
.github/workflows/generalization-smoke.yml 泛化 + holdout gate
```

## 下一批优先扩展

- 低空：TLOG 容器、PX4 ULog / ArduPilot DataFlash 深度时间线；802.11 management frame 与 RTP/RTSP capture 专项解析；自定义 MAVLink dialect CRC_EXTRA 表
- 固件：TRX/CHK/厂商升级头、UBI/UBIFS/JFFS2 deterministic carve、rootfs 解包后自动服务/密钥/更新链审计
- 车联网：UDS `dataFormatIdentifier` / 厂商自定义压缩与加密头识别、MQTT 车机协议证据
- AI：Isolation Forest / XGBoost / LightGBM 安全格式的真实树结构证据、ONNX/GGUF 深度检查、RAG 向量库/embedding 数据边界审计；继续坚持不执行不可信模型
- 区块链：跨 basic-block CFG evidence、DeFi 资产流/flash-loan callback 状态机、Diamond/EIP-2535
- 通用：KDF 派生链、artifact 证据包（binary + provenance + report）统一导出、环境自检
- UI：继续减少“工具墙”，让 workspace 的 finding / artifact / next-action 可以直接跳到对应证据与工具，同时保留专业视图可展开复核
