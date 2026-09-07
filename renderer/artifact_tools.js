(() => {
  function notify(message, isError = false) {
    const toast = document.querySelector('#toast');
    if (!toast) return;
    toast.textContent = message;
    toast.classList.toggle('error', isError);
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2600);
  }

  function resolveArtifact(kind, index) {
    if (!Number.isInteger(index) || index < 0) return null;
    if (kind === 'uds') return state.toolResult?.udsProgramming?.transfers?.[index]?.artifact || null;
    if (kind === 'mavftp') return state.toolResult?.ftpReassembly?.files?.[index]?.artifact || null;
    return null;
  }

  document.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-save-artifact]');
    if (!button) return;
    const kind = button.dataset.artifactKind;
    const index = Number(button.dataset.artifactIndex);
    const artifact = resolveArtifact(kind, index);
    if (!artifact) {
      notify('当前候选没有可导出的 complete artifact。', true);
      return;
    }
    button.disabled = true;
    try {
      const saved = await window.newcyber.saveArtifact(artifact);
      if (saved?.filePath) notify(`已导出 ${artifact.name} · ${saved.size} bytes · ${saved.sha256.slice(0, 12)}…`);
    } catch (error) {
      notify(error?.message || 'artifact 导出失败', true);
    } finally {
      button.disabled = false;
    }
  });
})();
