(() => {
  if (typeof DOMAINS==='undefined'||typeof TOOL_META==='undefined'||typeof renderResult!=='function') return;

  const additions={
    ai:[
      ['ai-model-extraction','模型窃取 / Extraction','导入黑盒 API 查询 transcript，统计概率/logit 暴露、重复查询稳定性、类别覆盖和模型抽取风险。'],
      ['ai-model-inversion','模型反演 / Inversion','分析概率、logit、embedding、gradient 暴露，并验证 reconstruction 与 reference 的数值相似度。']
    ],
    lowalt:[
      ['uav-regulatory-audit','低空监管 API','审计飞行许可、空域、无人机/运营人对象、审批状态机、BOLA、重放和地理时间边界。'],
      ['uav-gnss-audit','GNSS / GPS 欺骗','解析 NMEA GGA/RMC/GSV/GSA，检查 checksum、时间回退、位置物理一致性、卫星/SNR 和干扰候选。'],
      ['firmware-update-audit','固件升级信任链','审计下载→manifest→签名/hash→解包/解密→flash→anti-rollback 的升级链。']
    ]
  };

  TOOL_META['ai-model-extraction']={ domain:'ai',title:'模型窃取 / Extraction',label:'CSV/TSV/JSON API transcript',placeholder:'query,label,probabilities\nimg_001,3,"[0.01,0.02,0.94,0.03]"\nimg_002,1,"[0.04,0.90,0.03,0.03]"' };
  TOOL_META['ai-model-inversion']={ domain:'ai',title:'模型反演 / Inversion',label:'JSON/CSV：模型输出或 reference/reconstructed',placeholder:'[{"probabilities":[0.01,0.98,0.01],"reference":[0,1,0],"reconstructed":[0.01,0.97,0.02]}]' };
  TOOL_META['uav-regulatory-audit']={ domain:'lowalt',title:'低空监管 API',label:'OpenAPI / API 源码 / HTTP transcript',placeholder:'PATCH /api/flights/{flight_id}/approval\nAuthorization: Bearer ...\nbody: {"status":"approved","airspace_id":"A-01"}' };
  TOOL_META['uav-gnss-audit']={ domain:'lowalt',title:'GNSS / GPS 欺骗',label:'NMEA 日志',placeholder:'$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\n$GPRMC,123520,A,4807.038,N,01131.000,E,0.1,0.0,230394,,,A*00' };
  TOOL_META['firmware-update-audit']={ domain:'lowalt',title:'固件升级信任链',label:'升级脚本 / 源码 / manifest / strings',placeholder:'wget https://update.example/fw.bin\nsha256sum fw.bin\nverify_signature fw.bin.sig\nmtd write fw.bin firmware\nreboot' };

  for (const [domain,rows] of Object.entries(additions)) {
    const existing=new Set((DOMAINS[domain]?.tools||[]).map((x)=>x[0]));
    for (const row of rows) if (!existing.has(row[0])) DOMAINS[domain].tools.push(row);
  }

  const previousRender=renderResult;

  function findingCards(findings=[]) {
    if (!findings.length) return '<div class="result-empty">当前输入没有形成高优先级 finding。</div>';
    return findings.map((f)=>`<div class="finding ${esc(f.severity||'info')}"><span>${esc(f.severity||'info')}</span><div><b>${esc(f.title||f.id||'finding')}</b>${f.line?`<small>line ${esc(f.line)} · ${esc(f.id||'')}</small>`:`<small>${esc(f.id||'')}</small>`}<p>${esc(f.meaning||'')}</p>${f.evidence!=null?`<pre class="mini-pre">${esc(typeof f.evidence==='string'?f.evidence:JSON.stringify(f.evidence,null,2))}</pre>`:''}${f.fix?`<details><summary>修复 / 回归</summary><p><b>目标：</b>${esc(f.fix.target||'—')}</p><p><b>动作：</b>${esc(f.fix.action||'—')}</p><p><b>回归：</b>${esc(f.fix.regression||'—')}</p></details>`:''}</div></div>`).join('');
  }

  function actions(items=[]) {
    return items.length?`<details class="panel" open><summary><b>下一步</b> · ${items.length}</summary><div class="check-list">${items.map((x)=>`<p>${esc(x)}</p>`).join('')}</div></details>`:'';
  }

  function extraction(r) {
    return `<div class="result-stats"><div><b>${r.rows||0}</b><span>查询</span></div><div><b>${r.uniqueQueries||0}</b><span>Unique</span></div><div><b>${r.classCount||0}</b><span>类别</span></div><div><b>${esc(r.extractionExposure||'limited')}</b><span>Exposure</span></div></div>
      ${table(['指标','值'],[['完整概率向量',r.probabilityRows||0],['多维 score/logit',r.vectorRows||0],['高精度输出',r.highPrecisionRows||0],['重复 query',r.duplicateQueries||0],['稳定重复',r.deterministicDuplicates||0],['漂移重复',r.inconsistentDuplicates||0],['平均概率熵',r.meanProbabilityEntropy==null?'—':Number(r.meanProbabilityEntropy).toFixed(4)]])}
      ${findingCards(r.findings)}${actions(r.nextActions)}`;
  }

  function inversion(r) {
    return `<div class="result-stats"><div><b>${r.rows||0}</b><span>记录</span></div><div><b>${r.reconstructionPairs||0}</b><span>重建对</span></div><div><b>${r.embeddingVectors||0}</b><span>Embedding</span></div><div><b>${esc(r.privacyExposure||'limited')}</b><span>Exposure</span></div></div>
      ${table(['输出面','数量'],[['Probability vectors',r.probabilityVectors||0],['Logit vectors',r.logitVectors||0],['Embedding vectors',r.embeddingVectors||0],['Gradient rows',r.gradientRows||0]])}
      ${r.reconstructions?.length?`<details class="panel"><summary><b>重建指标</b> · ${r.reconstructions.length}</summary>${table(['Row','Dims','MAE','L2','L∞','Cosine'],r.reconstructions.slice(0,80).map((x)=>[x.row,x.dimensions,Number(x.mae).toPrecision(5),Number(x.l2).toPrecision(5),Number(x.linf).toPrecision(5),x.cosine==null?'—':Number(x.cosine).toFixed(5)]))}</details>`:''}
      ${findingCards(r.findings)}${actions(r.nextActions)}`;
  }

  function regulatory(r) {
    return `<div class="result-stats"><div><b>${r.summary?.high||0}</b><span>High</span></div><div><b>${r.summary?.medium||0}</b><span>Medium</span></div><div><b>${r.endpoints?.length||0}</b><span>Endpoints</span></div><div><b>${r.authEvidence?'YES':'NO'}</b><span>Auth Evidence</span></div></div>
      ${table(['攻击面','命中'],Object.entries(r.surfaces||{}))}
      ${r.endpoints?.length?`<details class="panel"><summary><b>监管接口</b> · ${r.endpoints.length}</summary>${table(['Line','Path'],r.endpoints.slice(0,100).map((x)=>[x.line,x.path]))}</details>`:''}
      ${findingCards(r.findings)}${actions(r.nextActions)}`;
  }

  function gnss(r) {
    return `<div class="result-stats"><div><b>${r.records||0}</b><span>NMEA</span></div><div><b>${r.jumps?.length||0}</b><span>位置跳变</span></div><div><b>${r.checksumFailed||0}</b><span>Checksum Fail</span></div><div><b>${r.gsv||0}</b><span>GSV</span></div></div>
      ${table(['类型','数量'],[['GGA',r.gga||0],['RMC',r.rmc||0],['GSV',r.gsv||0],['Time rollback',r.timeRollbacks?.length||0],['Speed mismatch',r.speedMismatches?.length||0],['Satellite jump',r.satelliteJumps?.length||0]])}
      ${findingCards(r.findings)}${actions(r.nextActions)}`;
  }

  function updateChain(r) {
    return `<div class="result-stats"><div><b>${r.summary?.high||0}</b><span>High</span></div><div><b>${r.summary?.medium||0}</b><span>Medium</span></div><div><b>${Object.values(r.stages||{}).filter(Boolean).length}</b><span>Stages</span></div><div><b>${r.flashTargets?.length||0}</b><span>Flash Targets</span></div></div>
      ${table(['阶段','识别'],Object.entries(r.stages||{}).map(([k,v])=>[k,v?'YES':'—']))}
      ${r.flashTargets?.length?`<p class="notice"><b>写入目标：</b>${esc(r.flashTargets.join(' · '))}</p>`:''}
      ${findingCards(r.findings)}${actions(r.nextActions)}`;
  }

  renderResult=function examDirectionRender(tool,result) {
    if (tool==='ai-model-extraction') return extraction(result);
    if (tool==='ai-model-inversion') return inversion(result);
    if (tool==='uav-regulatory-audit') return regulatory(result);
    if (tool==='uav-gnss-audit') return gnss(result);
    if (tool==='firmware-update-audit') return updateChain(result);
    return previousRender(tool,result);
  };

  render();
})();
