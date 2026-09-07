(() => {
  if (typeof renderResult !== 'function') return;

  const originalRenderResult = renderResult;
  renderResult = function renderMavlinkFtpResult(tool, result) {
    const baseHtml = originalRenderResult(tool, result);
    if (tool !== 'mavlink-hex' || !result) return baseHtml;
    const summary = result.securitySummary || {};
    const ftp = result.ftpEvents || [];
    const signedFrames = (result.frames || []).filter((frame) => frame.signed && frame.signature);
    if (!ftp.length && !signedFrames.length) return baseHtml;

    const signatureRows = signedFrames.slice(0, 120).map((frame) => [
      frame.seq,
      `${frame.sysid}:${frame.compid}`,
      frame.signature.linkId,
      frame.signature.timestamp,
      frame.signature.signatureHex,
      frame.msgid,
      frame.name
    ]);
    const ftpRows = ftp.slice(0, 160).map((event) => [
      event.frameIndex,
      `${event.sysid}:${event.compid}`,
      event.sequence,
      event.session,
      event.opcodeName,
      event.reqOpcodeName,
      event.offset,
      event.size,
      event.path || event.errorName || event.fileChunk?.dataHex?.slice(0, 48) || '—'
    ]);

    const panel = `<article class="panel"><div class="result-title"><b>MAVLink2 Signing / FTP</b><span>${summary.signedV2Frames || 0} signed · ${summary.ftpEventCount || 0} FTP</span></div>
      <div class="result-stats"><div><b>${summary.signedV2Frames || 0}</b><span>Signed v2</span></div><div><b>${Object.keys(summary.signingLinkCounts || {}).length}</b><span>Link IDs</span></div><div><b>${summary.signingTimestampRegressionCount || 0}</b><span>Timestamp rollback</span></div><div><b>${summary.ftpEventCount || 0}</b><span>FTP events</span></div></div>
      ${signatureRows.length ? table(['SEQ','SYS:COMP','Link ID','Signing timestamp','Signature','MSGID','消息'], signatureRows) : ''}
      ${ftpRows.length ? `<p class="notice">FILE_TRANSFER_PROTOCOL 已拆为 session/opcode/offset/path。OpenFileRO / ReadFile / BurstReadFile 可直接作为飞控文件系统取证入口；认证成功不等价于文件访问合理。</p>${table(['帧','源','FTP SEQ','Session','Opcode','Req Opcode','Offset','Size','Path/Data/Error'], ftpRows)}` : ''}
      <p class="notice">若同时从 EEPROM 提取到 32-byte signing key，可用核心 verifyMavlink2Signature() 对抓包逐帧离线确认密钥是否匹配；不要仅因帧带签名就推断密钥未复用。</p>
    </article>`;
    return `${panel}${baseHtml}`;
  };

  render();
})();
