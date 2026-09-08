const base = require('./finals_analyzer_batch9');
const { buildInvestigationGraph } = require('./investigation_graph');

async function scanWorkspace(rootPath) {
  const analysis = await base.scanWorkspace(rootPath);
  analysis.investigation = buildInvestigationGraph(analysis);
  analysis.version = Math.max(Number(analysis.version) || 1, 11);
  return analysis;
}

function buildInvestigationSection(analysis) {
  const graph = analysis?.investigation || buildInvestigationGraph(analysis);
  if (!graph?.focus?.length && !graph?.artifacts?.length) return '';
  const lines = [
    '## Investigation Graph',
    '',
    `- findings=${graph.summary.total}, high=${graph.summary.high}, confirmed=${graph.summary.confirmed}, artifacts=${graph.summary.artifacts}`,
    ''
  ];
  for (const node of graph.focus.slice(0, 12)) {
    lines.push(`### ${node.severity.toUpperCase()} · ${node.title}`, '');
    if (node.file) lines.push(`- 文件：\`${String(node.file).replace(/`/g, "'")}\`${node.line ? `，line ${node.line}` : ''}`);
    if (node.evidence) lines.push(`- Evidence：${String(node.evidence).replace(/\s+/g, ' ').slice(0, 700)}`);
    if (node.prerequisite) lines.push(`- Prerequisite：${node.prerequisite}`);
    lines.push(`- Exploitability：${node.exploitability}`);
    if (node.recommendedTool) lines.push(`- Recommended tool：${node.recommendedTool}`);
    if (node.nextAction) lines.push(`- Next action：${node.nextAction}`);
    if (node.fix) lines.push(`- Fix：${node.fix}`);
    if (node.regression) lines.push(`- Regression：${node.regression}`);
    lines.push('');
  }
  if (graph.artifacts.length) {
    lines.push('### Artifacts', '');
    for (const item of graph.artifacts.slice(0, 20)) lines.push(`- ${item.kind}: \`${item.name || 'artifact'}\` · ${item.size || 0} bytes · SHA-256 ${item.sha256 || 'unknown'} · source=${item.sourceFile}`);
    lines.push('');
  }
  return lines.join('\n');
}

function buildMarkdownReport(analysis, notes = '') {
  const report = base.buildMarkdownReport(analysis, notes);
  const section = buildInvestigationSection(analysis);
  return section ? `${report.trim()}\n\n${section}\n` : report;
}

module.exports = { ...base, scanWorkspace, buildMarkdownReport, buildInvestigationSection };
