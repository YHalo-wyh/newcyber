(() => {
  const UAV_TOOLS = new Set([
    'uav-recon-analyze','uav-spoof-analyze','uav-dos-analyze',
    'uav-injection-analyze','uav-leak-analyze','uav-challenge-matrix'
  ]);
  const previousRenderResult = renderResult;

  function smallList(items, empty='—') {
    const rows=(items||[]).filter(x=>x!==null&&x!==undefined&&x!=='').slice(0,18);
    if (!rows.length) return `<span class="uav32-empty">${esc(empty)}</span>`;
    return `<div class="uav32-chip-list">${rows.map(x=>`<span>${esc(String(x))}</span>`).join('')}</div>`;
  }

  function referenceBasis(result) {
    const refs=result.scenarioBasis||[];
    if (!refs.length) return '';
    return `<section class="panel uav32-reference"><div class="result-title"><b>REFERENCE BASIS</b><span>coverage provenance</span></div>${refs.map(ref=>`<div class="uav32-reference-row"><div><b>${esc(ref.title||ref.id)}</b><span>${esc(ref.level||'reference')}</span></div><p>${esc(ref.note||'')}</p><small>${esc((ref.architecture||[]).join(' → '))}</small></div>`).join('')}</section>`;
  }

  function roleCard(label, role) {
    if (!role) return '';
    return `<article class="uav32-role ${role.candidate?'candidate':'quiet'}"><div><span>${esc(label)}</span><b>${role.candidate?'CANDIDATE':'NO STRONG MATCH'}</b></div>${smallList(role.kinds,'no role evidence')}${role.evidence?.length?`<details><summary>Evidence · ${role.evidence.length}</summary><div class="uav32-lines">${role.evidence.slice(0,12).map(x=>`<code>${esc(x)}</code>`).join('')}</div></details>`:''}</article>`;
  }

  function roleEvidence(result) {
    const roles=result.roleEvidence;
    if (!roles) return '';
    return `<section class="panel"><div class="result-title"><b>ROLE MAP</b><span>Companion / GCS / Telemetry</span></div><div class="uav32-role-grid">${roleCard('COMPANION',roles.companion)}${roleCard('GCS',roles.gcs)}${roleCard('TELEMETRY',roles.telemetry)}</div></section>`;
  }

  function ros2Evidence(result) {
    const ros=result.ros2;
    if (!ros || !ros.graphObserved) return '';
    return `<section class="panel uav32-ros"><div class="result-title"><b>ROS 2 / DDS GRAPH</b><span>${ros.roguePublisherCandidate?'MULTI-PUBLISHER · ':''}${ros.floodCandidate?'LOSS · ':''}${ros.replayCandidate?'REPLAY · ':''}OBSERVED</span></div>
      <div class="result-stats"><div><b>${ros.topics?.length||0}</b><span>Topics</span></div><div><b>${ros.nodes?.length||0}</b><span>Nodes</span></div><div><b>${ros.types?.length||0}</b><span>Types</span></div><div><b>${ros.multiPublisherTopics?.length||0}</b><span>Multi Publisher</span></div></div>
      <div class="uav32-graph-grid"><div><b>HIGH-VALUE / CAMERA</b>${smallList(ros.cameraTopics,'none')}</div><div><b>MULTI-PUBLISHER</b>${smallList(ros.multiPublisherTopics,'none')}</div></div>
      <details><summary>Graph objects</summary><div class="uav32-graph-grid"><div><b>TOPICS</b>${smallList(ros.topics)}</div><div><b>NODES</b>${smallList(ros.nodes)}</div><div><b>TYPES</b>${smallList(ros.types)}</div><div><b>QoS</b>${smallList(ros.qos)}</div></div></details>
      ${ros.lossEvidence?.length?`<details open><summary>Availability evidence · ${ros.lossEvidence.length}</summary><div class="uav32-lines">${ros.lossEvidence.map(x=>`<code>${esc(x)}</code>`).join('')}</div></details>`:''}
      ${ros.replayEvidence?.length?`<details open><summary>Replay evidence · ${ros.replayEvidence.length}</summary><div class="uav32-lines">${ros.replayEvidence.map(x=>`<code>${esc(x)}</code>`).join('')}</div></details>`:''}
    </section>`;
  }

  function missionTransfer(result) {
    const mission=result.missionTransfer;
    if (!mission?.observed) return '';
    const sessions=mission.sessions||[];
    return `<section class="panel uav32-mission"><div class="result-title"><b>MISSION TRANSFER</b><span>${mission.completeSessions||0}/${sessions.length} complete</span></div>
      <div class="uav32-session-list">${sessions.slice(0,20).map((s,index)=>`<article class="${s.complete?'complete':'partial'}"><header><span>#${index+1}</span><b>${esc(s.requester)} → ${esc(s.responder)}</b><em>${s.complete?'COMPLETE':'PARTIAL'}</em></header><div class="uav32-session-metrics"><span>Declared <b>${s.declaredCount}</b></span><span>Items <b>${s.itemCount}</b></span><span>Requests <b>${s.requestCount}</b></span><span>Duplicate <b>${s.duplicateItemCount||0}</b></span></div><div class="uav32-seq"><span>SEQ</span><code>[${esc((s.itemSeq||[]).join(', '))}]</code></div>${s.missingSeq?.length?`<div class="uav32-seq missing"><span>MISSING</span><code>[${esc(s.missingSeq.join(', '))}]</code></div>`:''}</article>`).join('')}</div>
      <p class="notice">Mission download 只有覆盖 0..MISSION_COUNT-1 的真实序号后才标记 COMPLETE；重复 ITEM 不计作完整覆盖。</p>
    </section>`;
  }

  renderResult = function batch32UavScenarioResult(tool, result) {
    const html=previousRenderResult(tool,result);
    if (!UAV_TOOLS.has(tool) || !result) return html;
    return html + `<div class="uav32-intel">${referenceBasis(result)}${roleEvidence(result)}${ros2Evidence(result)}${missionTransfer(result)}</div>`;
  };
})();
