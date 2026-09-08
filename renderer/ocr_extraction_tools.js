(() => {
  if (typeof DOMAINS==='undefined'||typeof TOOL_META==='undefined'||typeof renderResult!=='function') return;
  const id='ai-ocr-extraction';
  TOOL_META[id]={domain:'ai',title:'OCR 模型窃取',label:'OCR API transcript（CSV/TSV/JSON）',placeholder:'image_id,text,char_confidences,boxes\nimg001,HELLO,"[0.99,0.98,0.97,0.99,0.96]","[[10,20,80,24]]"'};
  if (!(DOMAINS.ai.tools||[]).some((x)=>x[0]===id)) DOMAINS.ai.tools.push([id,'OCR 模型窃取','专门审计 OCR 黑盒 API：文本、字符/词置信度、logit、Bounding Box、重复查询稳定性和字符集覆盖。']);
  const previous=renderResult;
  renderResult=function ocrExtractionRender(tool,r) {
    if (tool!==id) return previous(tool,r);
    const cards=(r.findings||[]).map((f)=>`<div class="finding ${esc(f.severity||'info')}"><span>${esc(f.severity||'info')}</span><div><b>${esc(f.title||f.id)}</b><small>${esc(f.id||'')}</small><p>${esc(f.meaning||'')}</p><pre class="mini-pre">${esc(typeof f.evidence==='string'?f.evidence:JSON.stringify(f.evidence,null,2))}</pre></div></div>`).join('');
    return `<div class="result-stats"><div><b>${r.rows||0}</b><span>查询</span></div><div><b>${r.charsetSize||0}</b><span>字符覆盖</span></div><div><b>${r.charConfidenceRows||0}</b><span>字符置信度</span></div><div><b>${esc(r.extractionExposure||'limited')}</b><span>Exposure</span></div></div>
      ${table(['输出面','数量'],[['唯一 Query',r.uniqueQueries||0],['重复 Query',r.duplicateQueries||0],['稳定重复',r.stableDuplicates||0],['布局/Box',r.boxRows||0],['高精度 Box',r.highPrecisionBoxRows||0],['Logit/Probability',r.logitRows||0],['平均输出长度',Number(r.averageOutputLength||0).toFixed(2)]])}
      ${r.charset?`<details class="panel"><summary><b>字符集覆盖</b> · ${r.charsetSize}</summary><pre class="mini-pre">${esc(r.charset)}</pre></details>`:''}
      ${cards||'<div class="result-empty">当前 transcript 未形成高优先级模型抽取暴露 finding。</div>'}
      ${(r.nextActions||[]).length?`<details class="panel" open><summary><b>下一步</b> · ${r.nextActions.length}</summary><div class="check-list">${r.nextActions.map((x)=>`<p>${esc(x)}</p>`).join('')}</div></details>`:''}`;
  };
  render();
})();
