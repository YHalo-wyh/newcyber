module.exports = [
  {
    id: 'vehicle.can-differential', track: 'vehicle', domain: '车联网', title: 'CAN 信号差分与状态跃迁',
    tags: ['can', 'candump', 'signal', 'counter', 'state'],
    summary: '未知 CAN 协议先按 ID、周期、变化字节、计数器和事件前后差分缩小范围，不依赖固定 CAN ID。',
    evidence: ['同一 ID 出现稳定周期', '少数字节与动作/状态同步变化', '存在单调或回绕 counter'],
    prerequisites: ['有足够帧形成时间序列'],
    verify: ['比较事件窗口前后字节分布', '重复动作验证同一位置是否稳定响应'],
    falsePositives: ['CRC/counter 字节变化被误当业务信号'],
    actions: ['按事件窗口排序低频状态帧', '将疑似诊断流交给 ISO-TP/UDS'],
    mutations: ['can-id-remap', 'byte-position-shift', 'counter-wrap', 'noise-frame-insert']
  },
  {
    id: 'vehicle.isotp-reassembly', track: 'vehicle', domain: '车联网', title: 'ISO-TP 会话重组',
    tags: ['isotp', 'uds', 'first-frame', 'consecutive-frame', 'flow-control'],
    summary: '按 PCI 类型、声明长度和 CF sequence number 重组完整诊断 payload；序号缺失、冲突、回绕必须作为完整性证据。',
    evidence: ['PCI nibble 呈 SF/FF/CF/FC 结构', 'FF 声明长度大于单帧容量'],
    prerequisites: ['CAN ID/方向能够形成会话'],
    verify: ['最终 payload 长度等于 FF 声明长度', 'CF SN 连续并允许 F→0 回绕'],
    falsePositives: ['普通业务帧首字节偶然落在 PCI 范围'],
    actions: ['只对完整 session 做高置信 UDS 解码', '不完整 session 保留 gap map'],
    mutations: ['isotp-sn-wrap', 'cf-gap', 'duplicate-cf', 'can-id-remap']
  },
  {
    id: 'vehicle.uds-session-security', track: 'vehicle', domain: '车联网', title: 'UDS 会话与 SecurityAccess 状态机',
    tags: ['uds', '0x10', '0x27', 'seed-key', 'nrc'],
    summary: '把 DiagnosticSessionControl、SecurityAccess 与后续受保护服务关联成状态机，而不是孤立解码 SID。',
    evidence: ['0x10 切换会话', '0x27 奇数子功能请求 seed、偶数子功能提交 key', '0x33/0x35/0x36/0x37 NRC'],
    prerequisites: ['可按 ECU/Tester 方向串联请求与响应'],
    verify: ['成功 key 后受保护 DID/Memory/Programming 服务变为可达'],
    falsePositives: ['只出现单个 0x27 报文不足以说明算法可逆'],
    actions: ['提取 seed/key 样本对', '定位实现算法的固件/二进制或重复交互样本'],
    mutations: ['security-level-change', 'seed-length-change', 'nrc-delay', 'session-precondition']
  },
  {
    id: 'vehicle.uds-firmware-transfer', track: 'vehicle', domain: '车联网', title: 'UDS 固件下载链恢复',
    tags: ['0x34', '0x36', '0x37', 'firmware', 'bsc'],
    summary: 'RequestDownload → TransferData → RequestTransferExit 是通用刷写链。按 memory address、declared size、BSC 和传输完整性恢复固件 artifact。',
    evidence: ['0x34 给出 address/size/DFI', '连续 0x36 block', '0x37 结束'],
    prerequisites: ['TransferData 无 gap/冲突', '声明长度与恢复长度一致或差异可解释'],
    verify: ['计算 SHA-256', '检查固件 magic/向量表/字符串或后续校验'],
    falsePositives: ['DFI 非零可能表示压缩/加密，raw payload 不等于明文固件'],
    actions: ['完整时导出 firmware artifact', 'DFI 非零时继续识别压缩/加密头'],
    mutations: ['bsc-wrap', 'transfer-retransmit', 'declared-size-mismatch', 'nonzero-dfi']
  },
  {
    id: 'vehicle.uds-memory-did', track: 'vehicle', domain: '车联网', title: 'DID / Memory 读取面',
    tags: ['0x22', '0x23', 'did', 'vin', 'memory'],
    summary: 'ReadDataByIdentifier 与 ReadMemoryByAddress 常直接暴露身份、配置、密钥材料或 Flag。重点关联会话/安全级别与返回数据结构。',
    evidence: ['0x22 + 2-byte DID', '0x23 带 address/length 格式'],
    prerequisites: ['正确解析 ALFID 或 DID'],
    verify: ['重复读取稳定', '返回内容与 VIN/ASCII/结构体/固件地址空间一致'],
    falsePositives: ['厂商自定义 DID 语义未知'],
    actions: ['优先枚举题面/固件引用的 DID', '把返回 payload 送自动试解与文件识别'],
    mutations: ['did-remap', 'address-length-format', 'ascii-binary-response']
  },
  {
    id: 'vehicle.seed-key-recovery', track: 'vehicle', domain: '车联网', title: 'Seed-Key 算法恢复',
    tags: ['seed-key', 'securityaccess', 'reverse', 'xor', 'crc'],
    summary: '拿到多组 seed/key 后先验证线性/XOR/rotate/add/CRC 类简单关系，再结合 ECU 固件定位 SecurityAccess 实现。',
    evidence: ['存在多组确定 seed/key 对', 'key 长度固定'],
    prerequisites: ['至少两组以上样本更适合排除偶然关系'],
    verify: ['候选算法必须解释所有样本并预测新 seed'],
    falsePositives: ['单组样本可拟合大量伪算法'],
    actions: ['运行受限候选关系分析', '在固件中交叉搜索常量/调用路径'],
    mutations: ['xor-constant', 'rotate-add', 'crc-seed', 'seed-byteorder']
  },
  {
    id: 'vehicle.firmware-integrity', track: 'vehicle', domain: '车联网', title: '刷写完整性与校验链',
    tags: ['checksum', 'crc', 'signature', 'firmware', 'routinecontrol'],
    summary: '恢复固件后继续找 CRC/checksum/signature/RoutineControl 校验，判断修改固件需要满足哪种完整性约束。',
    evidence: ['0x31 RoutineControl 紧邻刷写结束', '固件尾部/头部存在 checksum/signature 字段'],
    prerequisites: ['固件候选完整或至少覆盖校验区域'],
    verify: ['重算校验值或定位签名验证函数'],
    falsePositives: ['普通 CRC 仅用于传输完整性，不代表安全签名'],
    actions: ['区分 checksum / MAC / signature', '把校验函数位置加入逆向优先级'],
    mutations: ['crc-polynomial', 'checksum-endian', 'signature-present']
  }
];
