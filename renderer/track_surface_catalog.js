(() => {
  if (typeof DOMAINS === 'undefined' || typeof TOOL_META === 'undefined') return;
  for (const domain of ['vehicle','ai','web3']) {
    if (!DOMAINS[domain]) continue;
    const rows=DOMAINS[domain].tools||(DOMAINS[domain].tools=[]);
    const existing=new Set(rows.map((row)=>row[0]));
    for (const [id,meta] of Object.entries(TOOL_META)) {
      if (meta?.domain!==domain||existing.has(id)) continue;
      rows.push([id,meta.title||id,meta.label||`${domain} tool`]);
      existing.add(id);
    }
  }
})();
