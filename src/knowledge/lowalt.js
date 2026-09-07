module.exports = [
  {
    id: 'lowalt.mavlink-framing-crc', track: 'lowalt', domain: '低空经济', title: 'MAVLink 帧边界与 CRC/Dialect',
    tags: ['mavlink', 'crc', 'crc-extra', 'dialect', 'v1', 'v2'],
    summary: '先确认 STX、payload length、msgid 与 X.25 CRC；未知 CRC_EXTRA 应保持 dialect unknown，不能把自定义消息直接判坏帧。',
    evidence: ['0xFE/0xFD 帧头', '帧长度与 payload length 一致'],
    prerequisites: ['已知 common.xml CRC_EXTRA 或有对应 dialect'],
    verify: ['CRC valid/invalid/unknown 三态', '连续帧 sequence 基本合理'],
    falsePositives: ['未知 dialect 的消息不能仅凭 CRC mismatch 判攻击'],
    actions: ['有效帧进入命令/FTP/签名分析', '未知消息记录 msgid 与 payload 供 dialect 恢复'],
    mutations: ['sysid-compid-change', 'unknown-crc-extra', 'crc-corruption', 'noise-prefix']
  },
  {
    id: 'lowalt.mavlink-signing', track: 'lowalt', domain: '低空经济', title: 'MAVLink2 Signing 信任链',
    tags: ['mavlink2', 'signing', 'sha256', 'link-id', 'timestamp'],
    summary: '签名 trailer 包含 link_id、48-bit timestamp 和 48-bit signature。验证签名之外，还要检查共享 key、时间戳回退和链路复用。',
    evidence: ['MAVLink2 incompat_flags 含 signing bit', '存在 13-byte signature trailer'],
    prerequisites: ['有 32-byte signing key 才能验证真实性'],
    verify: ['SHA256(key || packet || link_id || timestamp) 前 6 字节匹配', '同 link_id timestamp 单调'],
    falsePositives: ['签名有效不等于命令已授权', '共享 key 会放大单点泄露'],
    actions: ['从 EEPROM/配置中找 signing key', '按 sysid:compid:link_id 建签名时间线'],
    mutations: ['link-id-change', 'timestamp-rollback', 'shared-key-swarm', 'signature-bitflip']
  },
  {
    id: 'lowalt.mavlink-ftp', track: 'lowalt', domain: '低空经济', title: 'MAVLink FTP 文件恢复',
    tags: ['mavlink', 'ftp', 'openfilero', 'readfile', 'burstreadfile', 'filesystem'],
    summary: 'FILE_TRANSFER_PROTOCOL 的 OpenFileRO/ReadFile/BurstReadFile/ACK 可按 remote+session+offset 重组文件，重点处理乱序、重传、hole 与 overlap。',
    evidence: ['MSGID 110', 'FTP opcode 4/5/15/128/129', 'payload 中出现路径或 offset'],
    prerequisites: ['能区分 request/ACK 并跟踪 session'],
    verify: ['从 offset 0 连续覆盖到文件大小或可靠 EOF', '重叠数据一致'],
    falsePositives: ['只看到文件名不代表文件内容已完整获取'],
    actions: ['重组完整文件后生成 artifact', '对文件继续做 magic/解码/取证'],
    mutations: ['ftp-out-of-order', 'ftp-retransmit', 'ftp-hole', 'session-remap']
  },
  {
    id: 'lowalt.command-control', track: 'lowalt', domain: '低空经济', title: '控制命令与状态改变关联',
    tags: ['command_long', 'arm', 'takeoff', 'land', 'serial_control', 'mission'],
    summary: 'COMMAND_LONG/COMMAND_INT、SERIAL_CONTROL 与模式/arming 状态变化应按时间线关联，识别控制链而不是孤立看一个 msgid。',
    evidence: ['MSGID 76/75/126 等控制消息', '后续 HEARTBEAT/base_mode/custom_mode 改变'],
    prerequisites: ['有时间顺序或 sequence 信息'],
    verify: ['命令与 ACK/状态变化相互印证'],
    falsePositives: ['重复 telemetry 不能当控制动作'],
    actions: ['构建 command→ack→state 时间线', '高风险命令优先核对签名与来源'],
    mutations: ['command-id-change', 'ack-delay', 'state-change-noise']
  },
  {
    id: 'lowalt.parameter-surface', track: 'lowalt', domain: '低空经济', title: '参数读写与配置攻击面',
    tags: ['param_value', 'param_set', 'ardupilot', 'px4', 'configuration'],
    summary: '飞控参数可能直接影响 failsafe、GPS、arming、通信和安全策略。重点关注 PARAM_SET 与关键参数前后值。',
    evidence: ['PARAM_REQUEST/PARAM_VALUE/PARAM_SET 流量', '参数名可读'],
    prerequisites: ['能识别消息 dialect 和参数名'],
    verify: ['写入后读取值或飞控行为发生一致变化'],
    falsePositives: ['正常地面站初始化也会大量读取参数'],
    actions: ['按安全影响筛选参数', '建立参数变更差分'],
    mutations: ['param-name-change', 'value-boundary', 'read-write-order']
  },
  {
    id: 'lowalt.eeprom-secrets', track: 'lowalt', domain: '低空经济', title: 'EEPROM / 参数区密钥材料恢复',
    tags: ['eeprom', 'storage', 'signing-key', 'ardupilot', 'secrets'],
    summary: '飞控 EEPROM/参数存储中可能存在 MAVLink signing key、网络凭据和校准配置。先做结构化识别，再把密钥与抓包验证链关联。',
    evidence: ['固定长度 key record', '已知 StorageKey/参数结构附近出现高熵字段'],
    prerequisites: ['只静态解析存储镜像，不执行固件'],
    verify: ['恢复 key 能验证实际 MAVLink2 帧'],
    falsePositives: ['随机高熵区不等于密钥'],
    actions: ['对候选 key 做帧签名验证', '记录 offset 和结构 provenance'],
    mutations: ['key-offset-change', 'padding-change', 'multiple-key-records']
  },
  {
    id: 'lowalt.telemetry-timeline', track: 'lowalt', domain: '低空经济', title: '遥测 / 飞行日志时间线',
    tags: ['tlog', 'ulog', 'dataflash', 'gps', 'imu', 'timeline'],
    summary: '当题目给 TLOG/ULog/DataFlash 或密集遥测时，先按时间对齐 GPS、姿态、模式、arming、命令和异常事件，找状态转折。',
    evidence: ['连续时间戳 telemetry/log records', '模式或位置存在明显转折'],
    prerequisites: ['时间基准可统一或至少单调'],
    verify: ['多个传感器/状态字段在同一事件附近交叉印证'],
    falsePositives: ['GPS 漂移、传感器噪声不应直接视为攻击'],
    actions: ['生成事件窗口', '对异常窗口关联命令/参数/签名状态'],
    mutations: ['timestamp-offset', 'telemetry-noise', 'mode-transition']
  }
];
