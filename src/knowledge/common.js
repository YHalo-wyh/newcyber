module.exports = [
  {
    id: 'common.layered-encoding', track: 'common', domain: '通用', title: '多层编码与轻量变换链',
    tags: ['base64', 'hex', 'base32', 'xor', 'rot', 'gzip', 'zlib', 'encoding'],
    summary: '可疑文本往往不是单层编码。按可逆变换构建有限深度搜索树，并以 Flag、可打印率、文件魔数和结构一致性排序。',
    evidence: ['字符串满足 Hex/Base64/Base32/URL/转义等语法', '解码后出现另一种稳定编码或压缩头'],
    prerequisites: ['限制搜索深度和候选数', '每一步记录来源并按内容哈希去重'],
    verify: ['检查 Flag 格式', '检查 ZIP/ELF/PNG/PDF/gzip 等 magic', '复核完整变换链可重复'],
    falsePositives: ['随机高熵文本偶然满足 Base64 字符集', '单字节 XOR 偶然产生短可打印片段'],
    actions: ['运行自动试解链', '若得到二进制文件头则导出后继续分析'],
    mutations: ['encoding-stack', 'xor-key-byte', 'reverse-layer', 'compression-layer']
  },
  {
    id: 'common.crypto-context', track: 'common', domain: '通用', title: '上下文强加密参数恢复',
    tags: ['aes', 'sm4', 'cbc', 'ctr', 'gcm', 'key', 'iv', 'nonce'],
    summary: '先从源码/配置恢复算法、mode、key、IV/nonce/tag 与密文，再执行上下文明确的解密，不做无约束模式爆破。',
    evidence: ['加密 API 与 key/iv/ciphertext 同时出现', '变量长度与算法参数约束匹配'],
    prerequisites: ['明确算法和 mode', 'CBC/CTR/GCM 等模式具备所需 IV/nonce，GCM 具备 tag'],
    verify: ['解密结果可通过 PKCS#7/结构/magic/Flag 校验', '记录 key 与密文的原始编码解释'],
    falsePositives: ['32 字符文本既可能是 ASCII key 也可能是 16-byte Hex key'],
    actions: ['枚举仅由编码歧义产生的有限候选', '解密成功后继续进入自动编码/压缩链'],
    mutations: ['rename-crypto-vars', 'hex-base64-key', 'api-style-python-js', 'mode-explicitness']
  },
  {
    id: 'common.kdf-chain', track: 'common', domain: '通用', title: 'KDF / Hash 派生密钥链',
    tags: ['sha256', 'md5', 'pbkdf2', 'scrypt', 'hkdf', 'kdf'],
    summary: '比赛题常用 password/model output/secret 经 Hash 或 KDF 派生，再截断或切片作为对称密钥。重点恢复输入、salt、迭代参数、输出长度和截断方式。',
    evidence: ['digest/deriveKey 输出直接进入 AES/SM4', 'hexdigest 后存在切片或 bytes.fromhex'],
    prerequisites: ['派生输入和参数可从题面、源码、日志或上一步结果确定'],
    verify: ['重算派生值与程序中间值一致', '最终解密通过结构校验'],
    falsePositives: ['Hash 仅用于完整性校验而非密钥派生'],
    actions: ['构造 value → KDF/hash → slice → cipher 的数据流', '记录 salt/iterations/info/outputLength'],
    mutations: ['hash-truncate', 'pbkdf2-params', 'hex-digest-bytes', 'derived-key-slice']
  },
  {
    id: 'common.file-carving', track: 'common', domain: '通用', title: '文件魔数与嵌套产物恢复',
    tags: ['magic', 'zip', 'elf', 'png', 'pdf', 'sqlite', 'carving'],
    summary: '解码、解密、协议重组后的字节流应立即做文件类型识别、长度/哈希校验和可导出产物处理。',
    evidence: ['字节流包含稳定 magic', '容器头字段与实际长度基本一致'],
    prerequisites: ['产物覆盖连续，或明确标注 gap/冲突'],
    verify: ['SHA-256 固定', '重新解析文件头/目录结构'],
    falsePositives: ['短随机字节碰撞 magic', '缺块数据被零填后误判完整文件'],
    actions: ['导出完整 artifact', 'ZIP/固件/ELF 等进入下一分析器'],
    mutations: ['embedded-offset', 'nested-archive', 'truncated-file', 'duplicate-chunk']
  },
  {
    id: 'common.known-plaintext', track: 'common', domain: '通用', title: '已知明文与格式约束',
    tags: ['known-plaintext', 'flag', 'magic', 'crib'],
    summary: 'Flag 前缀、协议头、文件 magic、JSON/PNG/ZIP 固定字节可作为 XOR/流加密/错误 key 候选的强约束，而不是只靠可打印率。',
    evidence: ['题目给出 flag 前缀或预期文件类型', '密文长度与已知前缀足以约束 key/keystream'],
    prerequisites: ['已知明文位置和编码可合理确定'],
    verify: ['推导出的 key/keystream 能解释更多字节而非只解释前缀'],
    falsePositives: ['只匹配 2~3 字节的弱 magic'],
    actions: ['用已知前缀验证 XOR/key 候选', '将约束传给后续自动试解'],
    mutations: ['flag-prefix', 'magic-prefix', 'offset-crib']
  },
  {
    id: 'common.integrity-vs-encryption', track: 'common', domain: '通用', title: '区分加密、编码与完整性校验',
    tags: ['hash', 'hmac', 'checksum', 'crc', 'encryption'],
    summary: '先确认一个变换是否可逆。Hash/HMAC/CRC 通常是验证或派生环节，不应被当成“待解密算法”。',
    evidence: ['单向 digest 与比较操作相连', 'CRC/HMAC 结果进入校验分支'],
    prerequisites: ['能定位输入与比较目标'],
    verify: ['重算校验值', '检查是否存在碰撞、截断或弱输入空间'],
    falsePositives: ['Hash 输出后又被作为 AES key，此时它同时属于 KDF 链'],
    actions: ['分类为 verify / derive / encrypt 三类数据流', '避免无意义逆 Hash'],
    mutations: ['hash-as-key', 'checksum-compare', 'truncated-hmac']
  }
];
