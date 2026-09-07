(() => {
  const previousWorkspaceView = workspaceView;
  let cryptoArtifacts = [];

  function collect(analysis) {
    const items = [];
    for (const file of analysis?.files || []) {
      for (const candidate of file.metadata?.contextCrypto?.bestCandidates || []) {
        if (!candidate?.artifact) continue;
        items.push({ file: file.path, candidate, artifact: candidate.artifact });
      }
    }
    return items.slice(0, 4);
  }

  workspaceView = function contextCryptoWorkspaceView() {
    const html = previousWorkspaceView();
    if (!state.workspace) return html;
    cryptoArtifacts = collect(state.workspace);
    if (!cryptoArtifacts.length) return html;
    const item = cryptoArtifacts[0];
    const panel = `<article class="panel simple-clues"><div class="result-title"><b>强加密已恢复文件</b><span>${cryptoArtifacts.length} 个</span></div><div class="simple-clue medium"><div><strong>${esc(item.candidate.magic || '解密文件')}</strong><small>${esc(item.file)} · ${esc(item.candidate.cipher || '')}</small></div><button class="button" data-crypto-workspace-artifact="0">直接导出</button></div></article>`;
    const marker = '<details class="advanced-details">';
    return html.includes(marker) ? html.replace(marker, `${panel}${marker}`) : `${html}${panel}`;
  };

  document.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-crypto-workspace-artifact]');
    if (!button) return;
    const artifact = cryptoArtifacts[Number(button.dataset.cryptoWorkspaceArtifact)]?.artifact;
    if (!artifact) return toast('当前没有完整解密文件可导出', true);
    button.disabled = true;
    try {
      const saved = await window.newcyber.saveArtifact(artifact);
      if (saved?.filePath) toast(`已导出 ${artifact.name}`);
    } catch (error) {
      toast(error?.message || '导出失败', true);
    } finally {
      button.disabled = false;
    }
  });

  render();
})();
