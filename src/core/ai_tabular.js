function detectDelimiter(line) {
  const candidates = [',', '\t', ';'];
  let best = ',';
  let bestCount = -1;
  for (const delimiter of candidates) {
    let count = 0;
    let quoted = false;
    for (let i = 0; i < line.length; i += 1) {
      if (line[i] === '"') quoted = !quoted;
      else if (!quoted && line[i] === delimiter) count += 1;
    }
    if (count > bestCount) { best = delimiter; bestCount = count; }
  }
  return best;
}

function parseDelimitedLine(line, delimiter) {
  const out = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (quoted && line[i + 1] === '"') { current += '"'; i += 1; }
      else quoted = !quoted;
      continue;
    }
    if (ch === delimiter && !quoted) { out.push(current); current = ''; continue; }
    current += ch;
  }
  out.push(current);
  return out;
}

function quantile(sorted, q) {
  if (!sorted.length) return null;
  const pos = (sorted.length - 1) * q;
  const lower = Math.floor(pos);
  const upper = Math.ceil(pos);
  if (lower === upper) return sorted[lower];
  const weight = pos - lower;
  return sorted[lower] * (1 - weight) + sorted[upper] * weight;
}

function round(value, digits = 6) {
  return Number.isFinite(value) ? Number(value.toFixed(digits)) : null;
}

function correlation(xs, ys) {
  if (xs.length !== ys.length || xs.length < 2) return null;
  const meanX = xs.reduce((a, b) => a + b, 0) / xs.length;
  const meanY = ys.reduce((a, b) => a + b, 0) / ys.length;
  let covariance = 0;
  let varianceX = 0;
  let varianceY = 0;
  for (let i = 0; i < xs.length; i += 1) {
    const dx = xs[i] - meanX;
    const dy = ys[i] - meanY;
    covariance += dx * dy;
    varianceX += dx * dx;
    varianceY += dy * dy;
  }
  const denom = Math.sqrt(varianceX * varianceY);
  return denom ? covariance / denom : null;
}

function analyzeTabularDataset(input) {
  const text = String(input || '').replace(/^\uFEFF/, '').trim();
  if (!text) throw new Error('CSV/TSV 输入为空');
  const lines = text.split(/\r?\n/).filter((line) => line.trim().length);
  if (lines.length < 2) throw new Error('至少需要表头和一行数据');

  const delimiter = detectDelimiter(lines[0]);
  const headers = parseDelimitedLine(lines[0], delimiter).map((item, index) => item.trim() || `column_${index + 1}`);
  const rows = lines.slice(1, 5001).map((line, index) => {
    const cells = parseDelimitedLine(line, delimiter);
    const values = headers.map((_, column) => (cells[column] ?? '').trim());
    return { row: index + 1, values };
  });

  const columns = headers.map((name, columnIndex) => {
    const raw = rows.map((row) => row.values[columnIndex]);
    const numeric = [];
    let missing = 0;
    let nonFinite = 0;
    for (const value of raw) {
      if (value === '') { missing += 1; continue; }
      if (/^[+-]?(?:nan|inf(?:inity)?)$/i.test(value)) { nonFinite += 1; continue; }
      const number = Number(value);
      if (Number.isFinite(number)) numeric.push(number);
    }
    const numericRatio = rows.length ? numeric.length / rows.length : 0;
    if (numericRatio < 0.8) {
      return {
        name,
        type: 'text/mixed',
        count: rows.length,
        missing,
        nonFinite,
        unique: new Set(raw.filter(Boolean)).size
      };
    }
    const sorted = [...numeric].sort((a, b) => a - b);
    const mean = numeric.reduce((a, b) => a + b, 0) / numeric.length;
    const variance = numeric.reduce((sum, value) => sum + ((value - mean) ** 2), 0) / numeric.length;
    return {
      name,
      type: 'numeric',
      count: numeric.length,
      missing,
      nonFinite,
      min: round(sorted[0]),
      q05: round(quantile(sorted, 0.05)),
      q25: round(quantile(sorted, 0.25)),
      median: round(quantile(sorted, 0.5)),
      q75: round(quantile(sorted, 0.75)),
      q95: round(quantile(sorted, 0.95)),
      max: round(sorted[sorted.length - 1]),
      mean: round(mean),
      std: round(Math.sqrt(variance))
    };
  });

  const numericColumns = columns.filter((column) => column.type === 'numeric');
  const correlations = [];
  for (let i = 0; i < numericColumns.length; i += 1) {
    for (let j = i + 1; j < numericColumns.length; j += 1) {
      const leftIndex = headers.indexOf(numericColumns[i].name);
      const rightIndex = headers.indexOf(numericColumns[j].name);
      const xs = [];
      const ys = [];
      for (const row of rows) {
        const left = Number(row.values[leftIndex]);
        const right = Number(row.values[rightIndex]);
        if (Number.isFinite(left) && Number.isFinite(right)) { xs.push(left); ys.push(right); }
      }
      const value = correlation(xs, ys);
      if (Number.isFinite(value)) correlations.push({
        left: numericColumns[i].name,
        right: numericColumns[j].name,
        correlation: round(value)
      });
    }
  }
  correlations.sort((a, b) => Math.abs(b.correlation) - Math.abs(a.correlation));

  const center = Object.fromEntries(numericColumns.map((column) => [column.name, column.median]));
  const rankedRows = rows.map((row) => {
    let distance = 0;
    let dimensions = 0;
    for (const column of numericColumns) {
      const index = headers.indexOf(column.name);
      const value = Number(row.values[index]);
      if (!Number.isFinite(value) || !Number.isFinite(column.std) || column.std === 0) continue;
      distance += ((value - column.median) / column.std) ** 2;
      dimensions += 1;
    }
    return { row: row.row, score: dimensions ? Math.sqrt(distance / dimensions) : null };
  }).filter((item) => Number.isFinite(item.score)).sort((a, b) => a.score - b.score).slice(0, 12)
    .map((item) => ({ row: item.row, standardizedDistance: round(item.score) }));

  const nonFiniteCells = [];
  rows.forEach((row) => row.values.forEach((value, index) => {
    if (/^[+-]?(?:nan|inf(?:inity)?)$/i.test(value) && nonFiniteCells.length < 100) {
      nonFiniteCells.push({ row: row.row, column: headers[index], value });
    }
  }));

  return {
    format: delimiter === '\t' ? 'TSV' : delimiter === ';' ? 'CSV-semicolon' : 'CSV',
    rows: rows.length,
    columns: headers.length,
    numericColumns: numericColumns.length,
    columnStats: columns,
    strongestCorrelations: correlations.slice(0, 30),
    centerProfile: center,
    centerRows: rankedRows,
    nonFiniteCells,
    findings: [
      ...(nonFiniteCells.length ? [{ severity: 'high', id: 'non-finite-input', title: '数据中存在 NaN / Inf 非有限数', count: nonFiniteCells.length, message: '模型/API 边界若只做大小比较而未显式 isfinite 校验，NaN 可能绕过阈值逻辑；应人工验证服务端解析与模型行为。' }] : []),
      ...(numericColumns.length >= 4 ? [{ severity: 'info', id: 'multivariate-profile', title: '适合进行多维分布/异常检测分析', count: numericColumns.length, message: '已计算分位数、标准差与最强相关性。Isolation Forest 类题优先保持联合分布和相关结构，而不是逐列独立随机。' }] : [])
    ],
    hints: [
      'centerRows 是离各列中位数较近的真实样本索引，可作为人工构造候选的参考；不要直接复制原始行。',
      'strongestCorrelations 用于保留多变量结构。若题目要求绕 Isolation Forest，优先沿真实样本局部插值并保持强相关列关系。',
      '遇到 JSON/模型 API 时单独测试 NaN、Infinity、-Infinity、极大/极小有限数，并记录解析层、校验层和模型层各自行为。',
      '本工具只做确定性统计画像，不自动随机生成“对抗样本”，避免在线比赛中不可复现。'
    ]
  };
}

module.exports = { analyzeTabularDataset, parseDelimitedLine, detectDelimiter, quantile, correlation };
