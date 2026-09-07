module.exports = [
  {
    id: 'web3.external-contract-trust', track: 'web3', domain: '区块链', title: '外部合约接口信任边界',
    tags: ['interface', 'external-contract', 'callback', 'oracle', 'factory', 'mock'],
    summary: '当 external/public 函数接收接口/合约地址并直接相信其返回值时，应把该对象视为不可信输入。攻击者可实现同一 ABI，伪造 positions/factory/pool/oracle/token 等语义。',
    evidence: ['函数参数是 interface/contract/address 并被转换后调用', '返回值参与资产、权限、价格、池地址或后续外部调用'],
    prerequisites: ['参数来源未被 allowlist/factory/codehash/immutable 地址约束'],
    verify: ['构造最小 mock 合约返回极端值', '追踪返回值是否能到 transfer/mint/burn/call/delegatecall/storage'],
    falsePositives: ['参数虽然外部传入但被严格 registry/factory/codehash 验证'],
    actions: ['标记所有 caller-controlled external dependency', '优先构造恶意兼容接口验证业务假设'],
    mutations: ['interface-param-rename', 'method-return-extreme', 'validation-present-absent', 'callback-order']
  },
  {
    id: 'web3.delegatecall-storage', track: 'web3', domain: '区块链', title: 'DELEGATECALL / Storage Layout',
    tags: ['delegatecall', 'storage-collision', 'proxy', 'implementation'],
    summary: 'DELEGATECALL 在调用方 storage/context 中执行目标代码。通解是恢复 target 来源、implementation slot、storage layout 与升级权限，而不是只看到 opcode 就报漏洞。',
    evidence: ['delegatecall', 'EIP-1967/Beacon/UUPS slot', 'implementation 可写或可控'],
    prerequisites: ['能确认 target 或 storage slot 与 delegatecall 有数据流关系'],
    verify: ['写 implementation 后实际 delegatecall target 改变', '检查实现与代理 storage slot 冲突'],
    falsePositives: ['固定 implementation 且升级入口严格授权'],
    actions: ['恢复 proxy→implementation', '对 implementation 单独审计', '列出敏感 storage slot'],
    mutations: ['proxy-slot-change', 'implementation-write-guard', 'storage-layout-shift']
  },
  {
    id: 'web3.signature-replay', track: 'web3', domain: '区块链', title: '签名重放 / 域分离 / Malleability',
    tags: ['ecdsa', 'ecrecover', 'replay', 'nonce', 'domain-separator', 'permit'],
    summary: '签名题优先检查 message 是否绑定 chainId、contract、nonce、deadline、action 参数，以及 replay guard 是否基于 canonical message 而非原始签名字节。',
    evidence: ['ecrecover/ECDSA.recover', '签名 hash/used mapping', 'nonce/domain separator'],
    prerequisites: ['能恢复被签名的 digest'],
    verify: ['同一授权能否跨链/跨合约/换 s 值/换参数重放', 'invalid signature 是否可能得到 address(0)'],
    falsePositives: ['OpenZeppelin ECDSA + EIP-712 + nonce/deadline 完整绑定'],
    actions: ['重建 digest 字段表', '检查 low-s/canonicalization 与 nonce 消耗时机'],
    mutations: ['omit-chainid', 'omit-contract', 'raw-signature-hash', 'nonce-reuse', 'high-s']
  },
  {
    id: 'web3.abi-boundary', track: 'web3', domain: '区块链', title: 'ABI 编码边界 / Smuggling / Collision',
    tags: ['abi', 'calldata', 'encodePacked', 'smuggling', 'selector'],
    summary: '授权逻辑与实际执行 calldata 必须解析同一语义。动态 bytes 使用硬编码 offset、abi.encodePacked 连接多个动态值、手写 assembly 解码都应重点复核。',
    evidence: ['calldataload 固定偏移', 'bytes calldata + 动态外部调用', 'abi.encodePacked 多个动态参数'],
    prerequisites: ['存在签名/授权/白名单与实际执行 calldata 的分离'],
    verify: ['构造两组不同逻辑输入得到相同授权摘要或不同 selector 解释'],
    falsePositives: ['所有参数固定长度且使用标准 abi.decode'],
    actions: ['按 ABI head/tail 重算 offset', '比较授权 selector 与实际执行 selector'],
    mutations: ['dynamic-offset', 'packed-collision', 'selector-shift', 'tuple-reencode']
  },
  {
    id: 'web3.reentrancy-state-order', track: 'web3', domain: '区块链', title: '重入与状态更新顺序',
    tags: ['reentrancy', 'callback', 'transfer', 'hook', 'erc777', 'erc721'],
    summary: '核心不是搜索 call，而是识别“外部可控调用发生在关键状态更新之前”，以及 ERC721/777/custom token hook 是否提供回调。',
    evidence: ['外部调用/安全转账/callback', '调用后才更新余额、nonce、claim 状态'],
    prerequisites: ['攻击者能控制被调合约或 token hook'],
    verify: ['构造回调再次进入同一/关联入口', '检查 reentrancy guard 覆盖范围'],
    falsePositives: ['checks-effects-interactions 严格、状态已先更新、完整 nonReentrant'],
    actions: ['生成 external-call→state-write 顺序图', '检查跨函数重入而非只看同函数'],
    mutations: ['state-write-before-after-call', 'callback-token', 'cross-function-entry']
  },
  {
    id: 'web3.oracle-price', track: 'web3', domain: '区块链', title: 'Oracle / AMM 价格操纵',
    tags: ['oracle', 'amm', 'price', 'spot', 'twap', 'flashloan'],
    summary: '价格题先恢复价格来源、观察窗口、可操纵流动性与使用价格的敏感动作。单区块 spot price + 可借大额流动性通常是高价值组合。',
    evidence: ['getReserves/slot0/balance-based price', 'borrow/mint/liquidate/claim 依赖该价格'],
    prerequisites: ['攻击者能在价格读取前改变相关池状态'],
    verify: ['计算操纵前后敏感动作收益', '确认 TWAP/window/median 是否阻断单区块操纵'],
    falsePositives: ['足够长 TWAP、多源 median、操纵成本高于收益'],
    actions: ['画 source→price→sink 资产流', '估算所需资本与可借流动性'],
    mutations: ['spot-vs-twap', 'reserve-skew', 'flashloan-capital', 'decimal-mismatch']
  },
  {
    id: 'web3.flashloan-state', track: 'web3', domain: '区块链', title: 'Flash Loan / Snapshot 状态瞬时性',
    tags: ['flashloan', 'snapshot', 'governance', 'repayment', 'callback'],
    summary: 'Flash loan 本身不是漏洞。关键是某个安全假设把“瞬时余额/投票权/抵押率”当成长期状态，或 repayment accounting 可被 callback/推送架构绕过。',
    evidence: ['flashLoan/flashBorrow/callback', 'snapshot/governance/price/collateral 使用瞬时余额'],
    prerequisites: ['同一交易内能借入、触发敏感动作并偿还'],
    verify: ['构造 transaction-level 资产守恒表', '检查 snapshot 时点与 repayment 校验'],
    falsePositives: ['只提供 flashloan 但所有敏感状态使用历史快照或不可操纵 oracle'],
    actions: ['画单交易资金流', '标记 callback 前后关键状态'],
    mutations: ['snapshot-timing', 'push-vs-pull-repay', 'fee-rounding']
  },
  {
    id: 'web3.custom-token-semantics', track: 'web3', domain: '区块链', title: '自定义 Token / NFT 语义欺骗',
    tags: ['erc20', 'erc721', 'token', 'fee-on-transfer', 'callback', 'return-value'],
    summary: '不要假设外部 token 完全符合标准。返回值、decimals、fee-on-transfer、rebase、callback、ownerOf/transferFrom 语义都可能被攻击者控制。',
    evidence: ['函数接受 token/address 参数', '逻辑依赖 balanceOf/transferFrom/ownerOf/positions 等外部返回值'],
    prerequisites: ['token/manager 地址攻击者可选或来源验证不足'],
    verify: ['用最小 mock token 改变返回值/实际转账量/回调行为'],
    falsePositives: ['token 地址固定且实现 hash/registry 严格验证'],
    actions: ['比较 nominal amount 与实际 balance delta', '检查所有外部 token return/callback'],
    mutations: ['fee-on-transfer', 'false-return', 'reentrant-token', 'fake-balance']
  },
  {
    id: 'web3.low-level-call-result', track: 'web3', domain: '区块链', title: 'Low-level CALL 返回值与错误语义',
    tags: ['call', 'staticcall', 'delegatecall', 'success', 'returndata'],
    summary: '低级调用必须同时审计 target/data/value 和 success/returndata 处理。忽略 success 或信任恶意 revert/return data 会形成通用边界问题。',
    evidence: ['.call/.staticcall/.delegatecall', '返回值未绑定或 returndata 被直接 decode'],
    prerequisites: ['攻击者能影响 target 或返回数据'],
    verify: ['让 callee 返回 false/revert/伪造 returndata', '观察调用方状态是否仍继续'],
    falsePositives: ['使用 Address.functionCall 等安全封装并严格 decode'],
    actions: ['追踪 success 与 returndata 两条数据流', '检查失败路径是否改变状态'],
    mutations: ['ignore-success', 'fake-returndata', 'revert-data-shape']
  },
  {
    id: 'web3.txorigin-randomness', track: 'web3', domain: '区块链', title: '授权与链上弱随机源',
    tags: ['tx.origin', 'timestamp', 'blockhash', 'prevrandao', 'randomness'],
    summary: 'tx.origin 授权和可预测/可操纵的链属性随机数是经典通用能力。重点检查这些值是否直接决定权限、奖品或秘密。',
    evidence: ['tx.origin', 'block.timestamp/blockhash/prevrandao 进入关键判断或随机值'],
    prerequisites: ['攻击者能构造中间合约或影响/预测输入窗口'],
    verify: ['构造中间调用或枚举链上状态空间'],
    falsePositives: ['链属性仅作非安全元数据或防重放辅助字段'],
    actions: ['标记安全敏感使用点', '计算可预测范围与调用约束'],
    mutations: ['origin-vs-sender', 'timestamp-window', 'blockhash-range']
  }
];
