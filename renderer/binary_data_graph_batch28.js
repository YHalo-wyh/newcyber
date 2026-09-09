(() => {
  if (typeof toolView !== 'function') return;
  const previousToolView = toolView;
  toolView = function batch28BinaryDataGraphView(tool) {
    let html = previousToolView(tool);
    if (tool !== 'binary-data-graph' || !/x86-shortflow-v0\.1/.test(html)) return html;
    html = html
      .replace('EXPRESSION IR · NOT LIFTED','EXPRESSION IR · STANDALONE')
      .replace('ELF 原始模式目前不伪造可逆 Expression；切换 Listing 可恢复 XOR/CMP。','当前对象没有形成可证明的 standalone 可逆链；IDA Snapshot / Listing 可继续补充。')
      .replace('原始 ELF 本轮只做 Physical/Object/Relation；不在没有反汇编器时伪造 XOR/CMP。','当前对象暂未绑定到 standalone Operation；短程传播不会跨未知指令或控制流边界。')
      .replace('<div class="bdg-summary-bar">','<div class="bdg-summary-bar"><span class="bdg-shortflow-state"><b>SHORT</b> dataflow</span>');
    return html;
  };
  render();
})();
