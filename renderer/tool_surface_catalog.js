(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined' || !DOMAINS.lowalt) return;
  const rows = DOMAINS.lowalt.tools || (DOMAINS.lowalt.tools = []);
  const existing = new Set(rows.map((row) => row[0]));
  for (const [id, meta] of Object.entries(TOOL_META)) {
    if (meta?.domain !== 'lowalt' || existing.has(id)) continue;
    rows.push([id, meta.title || id, meta.label || '低空经济安全分析工具']);
    existing.add(id);
  }
})();
