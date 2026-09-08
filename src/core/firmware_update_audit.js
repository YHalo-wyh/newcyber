function lineNumberAt(text,index) { return text.slice(0,Math.max(0,index)).split(/\r?\n/).length; }
function evidenceAt(text,index,radius=280) { return text.slice(Math.max(0,index-100),Math.min(text.length,index+radius)).trim(); }

const RULES=Object.freeze([
  { id:'update-plain-http',severity:'high',title:'升级包通过明文 HTTP 获取',regex:/\b(?:curl|wget|fetch|download)[^\r\n]{0,240}\bhttp:\/\//gi,meaning:'中间人可替换升级包；即便后续有 hash，若 hash/manifest 同样来自不可信通道也可能失效。' },
  { id:'update-tls-disabled',severity:'high',title:'升级下载禁用 TLS 证书校验',regex:/\b(?:curl[^\r\n]*(?:-k|--insecure)|wget[^\r\n]*--no-check-certificate)\b/gi,meaning:'HTTPS 连接未验证服务端身份，会破坏升级源信任边界。' },
  { id:'update-md5-only',severity:'medium',title:'升级完整性仅见 MD5/弱 hash',regex:/\b(?:md5sum|MD5_Init|MD5_Update|MD5_Final)\b/gi,meaning:'单纯弱 hash 不提供发布者身份；应核对是否另有签名/公钥验证。' },
  { id:'update-shell-eval',severity:'high',title:'升级流程存在动态 shell/eval 执行',regex:/\b(?:eval|system|popen|os\.system|subprocess\.(?:run|Popen))\s*\([^\r\n]{0,300}(?:update|upgrade|firmware|image|cmd|command|path|url)/gi,meaning:'升级参数/路径/URL 若可控，可能从“写镜像”升级为命令执行边界。' },
  { id:'update-archive-traversal-surface',severity:'medium',title:'升级包解压后直接进入写入/安装链',regex:/\b(?:tar\s|unzip\s|extractall\(|ZipFile\(|TarFile\()[\s\S]{0,500}\b(?:flash|mtd|install|copy|move|rename|sysupgrade)\b/gi,meaning:'需核对路径穿越、符号链接和覆盖路径是否被约束。' },
  { id:'update-version-force',severity:'medium',title:'存在强制/跳过版本检查选项',regex:/\b(?:force[_ -]?upgrade|skip[_ -]?version|ignore[_ -]?version|allow[_ -]?downgrade|--force|no[_ -]?version[_ -]?check)\b/gi,meaning:'若生产路径可触达该开关，可能绕过 anti-rollback 或版本策略。' }
]);

function auditFirmwareUpdate(input) {
  const text=String(input||'');
  if (!text.trim()) throw new Error('请输入升级脚本/源码/manifest/字符串证据');
  const findings=[];
  for (const rule of RULES) {
    for (const match of text.matchAll(rule.regex)) findings.push({
      id:rule.id,severity:rule.severity,title:rule.title,line:lineNumberAt(text,match.index),evidence:evidenceAt(text,match.index),meaning:rule.meaning
    });
  }

  const stages={
    download:/(?:curl|wget|download|fetch|http:\/\/|https:\/\/|ota|firmware_url)/i.test(text),
    manifest:/(?:manifest|metadata|image[_ -]?info|version|build[_ -]?id)/i.test(text),
    hash:/(?:sha256|sha512|blake2|checksum|digest|md5)/i.test(text),
    signature:/(?:verify_signature|signature|openssl\s+dgst|ed25519|ecdsa|rsa|public[_ -]?key|x509|cms|pkcs7)/i.test(text),
    decrypt:/(?:decrypt|aes|chacha|gcm|cbc|ctr|kdf|hkdf|pbkdf)/i.test(text),
    version:/(?:version|rollback|anti[_ -]?rollback|minimum[_ -]?version|monotonic|fuse|counter)/i.test(text),
    extract:/(?:tar|unzip|squashfs|extract|decompress|gzip|xz)/i.test(text),
    flash:/(?:mtd\s+(?:write|erase)|flashcp|nandwrite|dd\s+if=|sysupgrade|fw_setenv|write[_ -]?flash|upgrade_partition|ota_apply)/i.test(text),
    reboot:/(?:reboot|restart|boot_slot|set_active|next_boot|bootcount)/i.test(text)
  };

  if (stages.flash && !stages.signature) findings.push({
    id:'update-no-signature-evidence',severity:'high',title:'写入固件链未见发布者签名验证',
    evidence:'检测到 flash/sysupgrade/mtd/dd 等写入动作，但全局未识别签名/公钥验证语义。',
    meaning:'若升级包来源可被替换，单纯 checksum/hash 只能检查传输完整性，不能证明镜像由可信发布者签发。'
  });
  if (stages.flash && !stages.hash && !stages.signature) findings.push({
    id:'update-no-integrity-evidence',severity:'high',title:'写入前未见 hash/signature 完整性校验',
    evidence:'存在升级写入动作，未识别 SHA/checksum/signature。',
    meaning:'需沿真实控制流确认是否存在其他组件完成完整性校验；否则升级链可能直接接受任意镜像。'
  });
  if (stages.version && !/(?:rollback|anti[_ -]?rollback|minimum[_ -]?version|monotonic|fuse|counter|downgrade.*reject|reject.*downgrade)/i.test(text) && stages.flash) findings.push({
    id:'update-rollback-policy-unclear',severity:'medium',title:'升级版本存在但 anti-rollback 证据不足',
    evidence:'检测到 version + flash 语义，未识别最小版本/单调计数/拒绝降级策略。',
    meaning:'检查旧版已知脆弱镜像是否仍可被合法签名后回滚安装。'
  });
  if (stages.signature && stages.extract && stages.flash) {
    const verifyIndex=text.search(/verify_signature|signature|openssl\s+dgst|ed25519|ecdsa|rsa/i);
    const extractIndex=text.search(/tar|unzip|extract|decompress/i);
    const flashIndex=text.search(/mtd\s+(?:write|erase)|flashcp|nandwrite|dd\s+if=|sysupgrade|write[_ -]?flash|ota_apply/i);
    if (verifyIndex>=0 && extractIndex>=0 && flashIndex>=0 && verifyIndex<extractIndex && extractIndex<flashIndex) findings.push({
      id:'update-signature-before-transform',severity:'info',title:'签名校验发生在解包/变换之前',
      evidence:`verify@${lineNumberAt(text,verifyIndex)} → extract@${lineNumberAt(text,extractIndex)} → flash@${lineNumberAt(text,flashIndex)}`,
      meaning:'这是重点复核点：确认签名覆盖的对象与最终写入字节完全绑定，避免“签已验证容器、写未验证派生文件”的差异。'
    });
  }

  const manifestFields=[...new Set([...text.matchAll(/\b(?:version|size|sha256|sha512|digest|signature|url|slot|partition|device|board|model|rollback[_ -]?index)\b/gi)].map((m)=>m[0].toLowerCase()))];
  const flashTargets=[...new Set([...text.matchAll(/(?:\/dev\/(?:mtd\w*|mmcblk\w*|ubi\w*)|\bmtd\d+\b|\b(?:kernel|rootfs|bootloader|recovery|slot_[ab]|system_[ab])\b)/gi)].map((m)=>m[0]))].slice(0,80);
  const nextActions=[];
  if (stages.flash) nextActions.push('画出 download → manifest → verify → extract/decrypt → flash → boot-slot 的实际数据流，并记录每一步输入 hash。');
  if (stages.signature) nextActions.push('确认公钥来源、签名算法、签名覆盖范围与最终写入镜像完全绑定；不要只看“调用过 verify”就判安全。');
  if (!stages.version && stages.flash) nextActions.push('补查 bootloader/secure storage 是否在其他层实现 anti-rollback；应用层没看到不代表一定没有。');
  if (flashTargets.length) nextActions.push(`已识别潜在写入目标：${flashTargets.slice(0,8).join(', ')}。优先核对 bootloader / rootfs / recovery 的信任差异。`);

  findings.sort((a,b)=>({high:0,medium:1,low:2,info:3}[a.severity]??9)-({high:0,medium:1,low:2,info:3}[b.severity]??9)||(a.line||0)-(b.line||0));
  return {
    stages,
    manifestFields,
    flashTargets,
    findings,
    summary:{ high:findings.filter((x)=>x.severity==='high').length, medium:findings.filter((x)=>x.severity==='medium').length, info:findings.filter((x)=>x.severity==='info').length },
    nextActions,
    notes:['该审计只根据静态文本/源码/字符串恢复升级信任链；真正结论必须回到实际控制流和最终写入字节。','“存在 SHA256”不等于安全升级；发布者身份、anti-rollback、解包后的对象绑定同样重要。']
  };
}

module.exports={ auditFirmwareUpdate };
