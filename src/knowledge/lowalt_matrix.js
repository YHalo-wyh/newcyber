const { SCENARIOS, CATEGORY_NAMES } = require('../core/uav_challenge_matrix');

const FALSE_POSITIVES = Object.freeze({
  recon: ['开放端口、SSID、banner 只能证明暴露面，不等于可利用漏洞。'],
  spoof: ['传感器噪声、估计器切换、时间基准错误可能造成合法不一致；至少需要来源/时间线/物理一致性之一补强。'],
  dos: ['单次丢包、模式拒绝、PreArm 失败可能是正常链路或安全机制；应证明持续性或攻击者相关来源。'],
  inject: ['出现控制命令不等于未授权注入；必须结合发送方、签名、会话和前后状态变化。'],
  leak: ['看到文件名/端点不等于内容已泄露；完整文件、凭据或会话数据要分别验证。'],
  firmware: ['magic 命中可能出现在压缩数据或误碰撞中；只有长度/结构可验证时才 carve 完整 artifact。']
});

module.exports = SCENARIOS.map((item) => ({
  id: `lowalt.matrix.${item.id}`,
  track: 'lowalt',
  domain: '低空经济',
  title: item.title,
  tags: [item.category, CATEGORY_NAMES[item.category], ...(item.tags || [])],
  summary: `${CATEGORY_NAMES[item.category]}风险检查项。目标不是看到关键字就定性，而是恢复“业务/设备对象 → 来源 → 协议/数据 → 状态变化或泄露结果 → 整改与复测”的证据链。`,
  evidence: item.evidence || [],
  prerequisites: item.mavlink?.length ? [`MAVLink 消息候选：${item.mavlink.join(', ')}`] : ['需要抓包、日志、配置、服务扫描或固件中的至少一种可复核证据'],
  verify: [item.action],
  falsePositives: FALSE_POSITIVES[item.category] || [],
  actions: [item.action, '若风险成立，记录具体修复措施，并用同一测试向量或等价负例完成复测关闭。'],
  assessment: {
    workflow: ['discover','verify','impact','remediate','retest'],
    automaticVerdict: 'candidate-only'
  },
  mutations: [
    'rename-device-and-stream',
    'change-sysid-compid-or-endpoint',
    'reorder-events-and-add-benign-noise',
    'positive-negative-repaired-control'
  ]
}));
