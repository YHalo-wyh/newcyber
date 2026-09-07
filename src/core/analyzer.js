const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { analyzeKnownFormat } = require('./formats');
const { parsePcapng } = require('./pcapng');
const { inspectPytorchZip } = require('./model');

const LIMITS = {
  maxFiles: 6000,
  hashBytes: 32 * 1024 * 1024,
  previewBytes: 256 * 1024,
  stringsBytes: 2 * 1024 * 1024,
  structuredBytes: 64 * 1024 * 1024,
  correlationTextBytes: 1024 * 1024
};

const IGNORED_DIRS = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build']);
const TEXT_EXTENSIONS = new Set([
  '.txt', '.md', '.json', '.jsonl', '.xml', '.yaml', '.yml', '.toml', '.ini', '.conf', '.cfg',
  '.log', '.csv', '.tsv', '.py', '.pyw', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.java',
  '.kt', '.kts', '.php', '.go', '.rs', '.c', '.cc', '.cpp', '.h', '.hpp', '.sh', '.ps1', '.bat',
  '.sql', '.html', '.htm', '.css', '.scss', '.vue', '.svelte', '.properties', '.env', '.dockerfile'
]);

const CATEGORY_RULES = {
  'AI / ML': {
    extensions: ['.pt', '.pth', '.onnx', '.h5', '.keras', '.safetensors', '.npy', '.npz', '.pkl', '.joblib'],
    keywords: ['torch', 'tensorflow', 'sklearn', 'transformers', 'whisper', 'inference', 'model', 'prompt', 'embedding', 'lora', 'tokenizer']
  },
  '取证 / 流量': {
    extensions: ['.pcap', '.pcapng', '.evtx', '.e01', '.raw', '.dd', '.mem', '.dmp', '.wav', '.mp3', '.flac'],
    keywords: ['wireshark', 'eventlog', 'volatility', 'registry', 'packet', 'spectrogram', 'forensic']
  },
  '恶意样本': {
    extensions: ['.exe', '.dll', '.ps1', '.vbs'],
    keywords: ['persistence', 'command_and_control', 'ransom', 'fernet', 'winreg', 'autorun', 'powershell -enc']
  }
};

const FINDING_RULES = [
  { id: 'shell-exec', severity: 'high', title: '可能存在命令拼接', regex: /(?:(?:os\.system|subprocess\.(?:call|run|Popen)|create_subprocess_shell|child_process\.exec|Runtime\.getRuntime\(\)\.exec|shell_exec|\bexec)\s*\([\s\S]{0,180}(?:\+|\$\{|format\(|f["'])|(?:cmd|command)\s*=\s*f["'][^\r\n]+["'][\s\S]{0,300}(?:os\.system|subprocess\.(?:call|run|Popen)|create_subprocess_shell|child_process\.exec)\s*\()/gi },
  { id: 'unsafe-pickle', severity: 'high', title: '不可信反序列化入口', regex: /(?:pickle\.loads?|joblib\.load|torch\.load|yaml\.load\s*\()/gi },
  { id: 'hardcoded-secret', severity: 'medium', title: '疑似硬编码密钥或令牌', regex: /(?:api[_-]?key|secret|token|password|passwd)\s*[=:]\s*["'][^"'\r\n]{6,}["']/gi }
];

function assertInside(rootPath, targetPath) {
  const root = path.resolve(rootPath);
  const target = path.resolve(targetPath);
  if (target !== root && !target.startsWith(root + path.sep)) throw new Error('文件路径超出赛题目录');
  return target;
}

function isProbablyText(buffer, ext) {
  if (TEXT_EXTENSIONS.has(ext)) return true;
  if (!buffer.length) return true;
  let suspicious = 0;
  for (const byte of buffer.subarray(0, 4096)) {
    if (byte === 0) return false;
    if (byte < 7 || (byte > 13 && byte < 32)) suspicious += 1;
  }
  return suspicious / Math.min(buffer.length, 4096) < 0.05;
}

function entropy(buffer) {
  if (!buffer.length) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte] += 1;
  let value = 0;
  for (const count of counts) {
    if (!count) continue;
    const probability = count / buffer.length;
    value -= probability * Math.log2(probability);
  }
  return Number(value.toFixed(3));
}

function printableStrings(buffer, minLength = 5) {
  return buffer.toString('latin1').match(new RegExp(`[\\x20-\\x7e]{${minLength},}`, 'g')) || [];
}

function detectType(buffer, ext) {
  const hex = buffer.subarray(0, 16).toString('hex');
  if (hex.startsWith('7f454c46')) return 'ELF 可执行文件';
  if (hex.startsWith('4d5a')) return 'PE/Windows 可执行文件';
  if (hex.startsWith('504b0304')) return ext === '.apk' ? 'Android APK' : ext === '.jar' ? 'Java JAR' : 'ZIP 压缩包';
  if (hex.startsWith('25504446')) return 'PDF 文档';
  if (hex.startsWith('52494646') && buffer.subarray(8, 12).toString() === 'WAVE') return 'WAV 音频';
  if (['d4c3b2a1', 'a1b2c3d4', '4d3cb2a1', 'a1b23c4d'].some((magic) => hex.startsWith(magic))) return 'PCAP 流量';
  if (hex.startsWith('0a0d0d0a')) return 'PCAPNG 流量';
  if (buffer.subarray(0, 15).toString() === 'SQLite format 3') return 'SQLite 数据库';
  return isProbablyText(buffer, ext) ? '文本/源码' : '二进制数据';
}

function extractSignals(text, relativePath) {
  const flags = [...new Set(text.match(/(?:flag|ctf|dart|FLAG|CTF)\{[^}\r\n]{1,200}\}/g) || [])].slice(0, 50);
  const urls = [...new Set(text.match(/https?:\/\/[^\s"'<>]{4,300}/g) || [])].slice(0, 50);
  const ips = [...new Set(text.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || [])].slice(0, 50);
  const findings = [];
  for (const rule of FINDING_RULES) {
    rule.regex.lastIndex = 0;
    const matches = text.match(rule.regex);
    if (matches?.length) findings.push({
      id: `${rule.id}:${relativePath}`,
      severity: rule.severity,
      title: rule.title,
      file: relativePath,
      count: matches.length,
      evidence: matches[0].slice(0, 220)
    });
  }
  return { flags, urls, ips, findings };
}

function scoreCategories(ext, text, scores) {
  const lower = text.toLowerCase();
  for (const [category, rule] of Object.entries(CATEGORY_RULES)) {
    if (rule.extensions.includes(ext)) scores[category] += 4;
    for (const keyword of rule.keywords) {
      if (lower.includes(keyword.toLowerCase())) scores[category] += 1;
    }
  }
}

async function walk(rootPath) {
  const files = [];
  async function visit(current) {
    if (files.length >= LIMITS.maxFiles) return;
    const entries = await fsp.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (files.length >= LIMITS.maxFiles) break;
      if (entry.isSymbolicLink()) continue;
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name.toLowerCase())) await visit(fullPath);
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  }
  await visit(rootPath);
  return files;
}

async function readHead(filePath, size) {
  const handle = await fsp.open(filePath, 'r');
  try {
    const buffer = Buffer.alloc(size);
    const { bytesRead } = await handle.read(buffer, 0, size, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

async function structuredMetadata(filePath, stat, head, type, ext) {
  let buffer = head;
  if ((type === 'PCAPNG 流量' || ['.pt', '.pth'].includes(ext)) && stat.size <= LIMITS.structuredBytes && head.length !== stat.size) {
    buffer = await fsp.readFile(filePath);
  }
  if (type === 'PCAPNG 流量') return parsePcapng(buffer);
  if (['.pt', '.pth'].includes(ext)) {
    const pytorch = inspectPytorchZip(buffer);
    if (pytorch) return { ...pytorch, safeModelInspection: true };
  }
  return analyzeKnownFormat(buffer, type, ext);
}

async function analyzeFile(rootPath, filePath, categoryScores) {
  const stat = await fsp.stat(filePath);
  const relativePath = path.relative(rootPath, filePath);
  const ext = path.extname(filePath).toLowerCase();
  const head = await readHead(filePath, Math.min(stat.size, LIMITS.stringsBytes));
  const type = detectType(head, ext);
  const text = isProbablyText(head, ext) ? head.toString('utf8') : printableStrings(head).join('\n');
  scoreCategories(ext, text, categoryScores);
  const signals = extractSignals(text, relativePath);
  const hashBuffer = stat.size <= LIMITS.hashBytes ? await fsp.readFile(filePath) : head;
  const sha256 = crypto.createHash('sha256').update(hashBuffer).digest('hex');
  const metadata = await structuredMetadata(filePath, stat, head, type, ext);
  return {
    path: relativePath,
    name: path.basename(filePath),
    extension: ext || '—',
    size: stat.size,
    modifiedAt: stat.mtime.toISOString(),
    type,
    sha256,
    partialHash: stat.size > LIMITS.hashBytes,
    entropy: entropy(head),
    flags: signals.flags,
    urls: signals.urls,
    ips: signals.ips,
    findings: signals.findings,
    metadata
  };
}

async function deriveWorkspaceInsights(root, files) {
  const findings = [];
  const insights = [];

  for (const file of files) {
    const can = file.metadata?.can;
    if (!can?.ids?.length) continue;
    const signal188 = can.ids.find((item) => item.id === '0x188');
    const rightTransition = signal188?.transitions?.find((event) => event.changes?.some((change) => change.byteIndex === 0 && (change.setBits & 0x02) === 0x02));
    if (rightTransition) {
      insights.push({
        kind: 'can-state-transition',
        title: 'CAN 0x188 首次置位 0x02',
        file: file.path,
        frameIndex: rightTransition.frameIndex,
        packetIndex: rightTransition.packetIndex,
        timestamp: rightTransition.timestamp,
        payload: rightTransition.payload,
        rawFrameHex: rightTransition.rawFrameHex,
        evidence: `frame=${rightTransition.frameIndex}, payload=${rightTransition.payload}, raw=${rightTransition.rawFrameHex || 'n/a'}`
      });
    }
  }

  const textFiles = files.filter((file) => ['.txt', '.log', '.md'].includes(file.extension) && file.size <= LIMITS.correlationTextBytes);
  const textChunks = [];
  for (const file of textFiles) {
    try {
      const content = await fsp.readFile(path.join(root, file.path), 'utf8');
      textChunks.push({ file: file.path, content, lower: content.toLowerCase() });
    } catch {}
  }
  const deniesAdapter = textChunks.find((item) => /no\s+(?:extra\s+)?adapter|without\s+(?:an\s+)?adapter|未(?:使用|加载).{0,20}adapter|没有.{0,20}adapter/i.test(item.content));
  const modelWithAdapter = files.find((file) => ['.pt', '.pth'].includes(file.extension) && file.metadata?.pickleStrings?.some((value) => /adapter/i.test(value)));
  if (deniesAdapter && modelWithAdapter) {
    const adapterNames = modelWithAdapter.metadata.pickleStrings.filter((value) => /adapter/i.test(value)).slice(0, 8);
    findings.push({
      id: `model-log-contradiction:${modelWithAdapter.path}`,
      severity: 'high',
      title: '模型结构与训练记录矛盾：发现额外 Adapter 参数',
      file: modelWithAdapter.path,
      count: adapterNames.length || 1,
      evidence: `${deniesAdapter.file} 声明未使用 adapter；模型出现 ${adapterNames.join(', ')}`
    });
    insights.push({
      kind: 'model-log-contradiction',
      title: '训练记录否认 Adapter，但 checkpoint 中存在 Adapter',
      file: modelWithAdapter.path,
      relatedFile: deniesAdapter.file,
      names: adapterNames,
      storageCount: modelWithAdapter.metadata.storageCount,
      largestStorages: [...(modelWithAdapter.metadata.storageEntries || [])].sort((a, b) => b.uncompressedSize - a.uncompressedSize).slice(0, 3)
    });
  }

  return { findings, insights };
}

function recommendations(categories, files, findings, insights = []) {
  const top = categories.filter((item) => item.score > 0).slice(0, 3).map((item) => item.name);
  const items = ['先固定原始附件哈希，所有解包和修改都在副本中进行。'];
  if (top.includes('AI / ML')) items.push('模型文件按不可信工件处理：先检查结构和元数据，避免直接 pickle/torch.load。');
  if (top.includes('取证 / 流量')) items.push('按时间线关联流量、日志和业务动作；音频题优先查看频谱、分段长度与重复模式。');
  if (findings.some((item) => item.title.includes('命令拼接'))) items.push('优先核对语音识别、模型输出等不可信文本是否进入 shell 命令。');
  if (files.some((file) => file.type === 'PCAP 流量' || file.type === 'PCAPNG 流量')) items.push('对 PCAP/PCAPNG 建立会话或总线事件清单，并将状态跃迁与题目业务动作互相印证。');
  if (insights.some((item) => item.kind === 'model-log-contradiction')) items.push('优先检查 checkpoint 中训练记录未声明的参数/adapter，并对异常 storage 做字节级提取与编码识别。');
  return items;
}

async function scanWorkspace(rootPath) {
  if (!rootPath || typeof rootPath !== 'string') throw new Error('未选择赛题目录');
  const root = path.resolve(rootPath);
  const stat = await fsp.stat(root);
  if (!stat.isDirectory()) throw new Error('所选路径不是目录');
  const paths = await walk(root);
  const categoryScores = Object.fromEntries(Object.keys(CATEGORY_RULES).map((key) => [key, 0]));
  const files = new Array(paths.length);
  let nextIndex = 0;
  async function worker() {
    while (nextIndex < paths.length) {
      const index = nextIndex;
      nextIndex += 1;
      files[index] = await analyzeFile(root, paths[index], categoryScores);
    }
  }
  await Promise.all(Array.from({ length: Math.min(8, paths.length) }, worker));
  const categories = Object.entries(categoryScores)
    .map(([name, score]) => ({ name, score }))
    .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  const severityOrder = { high: 0, medium: 1, low: 2 };
  const derived = await deriveWorkspaceInsights(root, files);
  const findings = [...files.flatMap((file) => file.findings), ...derived.findings].sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  const flags = files.flatMap((file) => file.flags.map((value) => ({ value, file: file.path })));
  const urls = [...new Set(files.flatMap((file) => file.urls))];
  const ips = [...new Set(files.flatMap((file) => file.ips))];
  return {
    version: 2,
    scannedAt: new Date().toISOString(),
    workspacePath: root,
    workspaceName: path.basename(root),
    truncated: paths.length >= LIMITS.maxFiles,
    stats: {
      files: files.length,
      bytes: files.reduce((sum, file) => sum + file.size, 0),
      findings: findings.length,
      flags: flags.length,
      insights: derived.insights.length
    },
    categories,
    files,
    findings,
    insights: derived.insights,
    candidates: { flags, urls, ips },
    recommendations: recommendations(categories, files, findings, derived.insights)
  };
}

async function inspectFile(rootPath, relativePath) {
  const root = path.resolve(rootPath);
  const filePath = assertInside(root, path.join(root, relativePath));
  const stat = await fsp.stat(filePath);
  if (!stat.isFile()) throw new Error('目标不是文件');
  const buffer = await readHead(filePath, Math.min(stat.size, LIMITS.previewBytes));
  const ext = path.extname(filePath).toLowerCase();
  const binary = !isProbablyText(buffer, ext);
  const text = binary ? printableStrings(buffer).slice(0, 400).join('\n') : buffer.toString('utf8');
  return { text: text || '未提取到可显示字符串。', truncated: stat.size > LIMITS.previewBytes, binary };
}

function buildMarkdownReport(analysis, notes = '') {
  const topCategories = analysis.categories.filter((item) => item.score > 0).slice(0, 4);
  const lines = [
    `# NewCyber 赛题分析报告：${analysis.workspaceName}`,
    '',
    `- 分析时间：${analysis.scannedAt}`,
    `- 赛题目录：\`${analysis.workspacePath}\``,
    `- 文件数量：${analysis.stats.files}`,
    `- 总大小：${analysis.stats.bytes} bytes`,
    '',
    '## 初步分类',
    '',
    ...(topCategories.length ? topCategories.map((item) => `- ${item.name}：${item.score}`) : ['- 暂无明确分类，建议从题面和运行行为继续确认。']),
    '',
    '## 关键发现',
    '',
    ...(analysis.findings.length ? analysis.findings.map((item) => `- **${item.severity.toUpperCase()}** ${item.title} — \`${item.file}\`（${item.count} 处）${item.evidence ? `：${item.evidence}` : ''}`) : ['- 静态扫描未发现明显高风险模式。']),
    '',
    '## 确定性洞察',
    '',
    ...((analysis.insights || []).length ? analysis.insights.map((item) => `- **${item.title}** — \`${item.file}\`${item.evidence ? `：${item.evidence}` : ''}`) : ['- 暂无。']),
    '',
    '## Flag 候选',
    '',
    ...(analysis.candidates.flags.length ? analysis.candidates.flags.map((item) => `- \`${item.value}\` — \`${item.file}\``) : ['- 暂无。']),
    '',
    '## 建议路线',
    '',
    ...analysis.recommendations.map((item, index) => `${index + 1}. ${item}`),
    '',
    '## 文件证据',
    '',
    '| 文件 | 类型 | 大小 | SHA-256 |',
    '| --- | --- | ---: | --- |',
    ...analysis.files.map((file) => `| \`${file.path.replace(/\|/g, '\\|')}\` | ${file.type} | ${file.size} | \`${file.sha256}${file.partialHash ? '（前 2 MiB）' : ''}\` |`),
    '',
    '## 队伍记录',
    '',
    notes.trim() || '无。',
    '',
    '> 本报告由 NewCyber 的只读静态分析生成。结论需要结合题目环境和运行行为验证。',
    ''
  ];
  return lines.join('\n');
}

module.exports = { scanWorkspace, inspectFile, buildMarkdownReport, detectType, entropy, extractSignals };