const crypto = require('crypto');
const { createBinaryArtifact } = require('./artifacts');

function bytesFromSession(session) {
  if (!session?.complete || !session.payload || !/^[0-9a-f]+$/i.test(session.payload) || session.payload.length % 2) return null;
  return [...Buffer.from(session.payload, 'hex')];
}

function readBigInt(bytes) {
  return bytes.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);
}

function parseRequestDownload(bytes) {
  if (bytes[0] !== 0x34 || bytes.length < 3) return null;
  const dataFormatIdentifier = bytes[1];
  const alfid = bytes[2];
  const addressLength = alfid & 0x0f;
  const sizeLength = alfid >> 4;
  const required = 3 + addressLength + sizeLength;
  if (!addressLength || !sizeLength || bytes.length < required) return {
    dataFormatIdentifier: `0x${dataFormatIdentifier.toString(16).padStart(2, '0')}`,
    addressAndLengthFormatIdentifier: `0x${alfid.toString(16).padStart(2, '0')}`,
    addressLength,
    sizeLength,
    valid: false
  };
  const addressBytes = bytes.slice(3, 3 + addressLength);
  const sizeBytes = bytes.slice(3 + addressLength, required);
  const address = readBigInt(addressBytes);
  const size = readBigInt(sizeBytes);
  return {
    dataFormatIdentifier: `0x${dataFormatIdentifier.toString(16).padStart(2, '0')}`,
    addressAndLengthFormatIdentifier: `0x${alfid.toString(16).padStart(2, '0')}`,
    addressLength,
    sizeLength,
    address: `0x${address.toString(16)}`,
    size: size.toString(),
    sizeHex: `0x${Buffer.from(sizeBytes).toString('hex')}`,
    valid: true
  };
}

function artifactName(state, digest) {
  const can = String(state.canId || 'unknown').replace(/[^0-9a-z]+/gi, '-').replace(/^-|-$/g, '') || 'unknown';
  const address = String(state.requestDownload?.address || 'unknown').replace(/^0x/i, '');
  const raw = state.requestDownload?.dataFormatIdentifier && state.requestDownload.dataFormatIdentifier !== '0x00';
  return `uds-${can}-${address}-${digest.slice(0, 12)}${raw ? '.transfer.bin' : '.firmware.bin'}`;
}

function finalize(state, complete, endSessionIndex = null) {
  const blockMap = [];
  let offset = 0;
  for (const block of state.blocks) {
    blockMap.push({
      counter: block.counter,
      sessionIndex: block.sessionIndex,
      offset,
      length: block.data.length,
      endOffset: offset + block.data.length
    });
    offset += block.data.length;
  }

  const firmware = Buffer.concat(state.blocks.map((block) => block.data));
  const declaredSize = state.requestDownload?.valid ? BigInt(state.requestDownload.size) : null;
  const actualSize = BigInt(firmware.length);
  const sizeMatches = declaredSize == null ? null : declaredSize === actualSize;
  const errors = [...state.errors];
  if (declaredSize != null && !sizeMatches) errors.push({
    id: 'declared-size-mismatch',
    declared: declaredSize.toString(),
    actual: actualSize.toString()
  });

  const digest = crypto.createHash('sha256').update(firmware).digest('hex');
  const confidence = complete && !errors.length && sizeMatches !== false ? 'high' : complete ? 'medium' : 'low';
  const artifactReady = complete && firmware.length > 0 && !errors.length && sizeMatches !== false;
  const rawTransferPayload = Boolean(state.requestDownload?.dataFormatIdentifier && state.requestDownload.dataFormatIdentifier !== '0x00');
  const artifact = artifactReady ? createBinaryArtifact({
    name: artifactName(state, digest),
    buffer: firmware,
    completeness: 'complete',
    provenance: blockMap.map((block) => ({
      source: 'UDS TransferData',
      sessionIndex: block.sessionIndex,
      blockSequenceCounter: block.counter,
      offset: block.offset,
      length: block.length
    })),
    metadata: {
      kind: rawTransferPayload ? 'uds-raw-transfer-payload' : 'uds-firmware-candidate',
      canId: state.canId,
      address: state.requestDownload?.address || null,
      declaredSize: state.requestDownload?.size || null,
      dataFormatIdentifier: state.requestDownload?.dataFormatIdentifier || null,
      rawTransferPayload
    }
  }) : null;

  return {
    canId: state.canId,
    startSessionIndex: state.startSessionIndex,
    endSessionIndex,
    programmingSessionSeen: state.programmingSessionSeen,
    requestDownload: state.requestDownload,
    blockCount: state.blocks.length,
    blockSequenceCounters: state.blocks.map((block) => block.counter),
    blockMap,
    duplicateBlocks: state.duplicateBlocks,
    firmwareSize: firmware.length,
    firmwareHex: firmware.toString('hex'),
    firmwareSha256: digest,
    declaredSizeMatches: sizeMatches,
    complete,
    errors,
    confidence,
    artifactReady,
    artifact
  };
}

function reconstructUdsProgramming(isoTpSessions) {
  const sessions = Array.isArray(isoTpSessions) ? isoTpSessions : [];
  const active = new Map();
  const transfers = [];
  const programmingSeen = new Map();

  const startOrphan = (session, index) => ({
    canId: session.canId,
    startSessionIndex: index,
    programmingSessionSeen: Boolean(programmingSeen.get(session.canId)),
    requestDownload: null,
    blocks: [],
    duplicateBlocks: [],
    errors: [{ id: 'missing-request-download' }],
    lastCounter: null
  });

  for (let index = 0; index < sessions.length; index += 1) {
    const session = sessions[index];
    const bytes = bytesFromSession(session);
    if (!bytes?.length) continue;
    const sid = bytes[0];
    const canId = session.canId || 'unknown';

    if (sid === 0x10 && bytes[1] === 0x02) {
      programmingSeen.set(canId, true);
      continue;
    }

    if (sid === 0x34) {
      const previous = active.get(canId);
      if (previous) transfers.push(finalize(previous, false, index - 1));
      active.set(canId, {
        canId,
        startSessionIndex: index,
        programmingSessionSeen: Boolean(programmingSeen.get(canId)),
        requestDownload: parseRequestDownload(bytes),
        blocks: [],
        duplicateBlocks: [],
        errors: [],
        lastCounter: null
      });
      continue;
    }

    if (sid === 0x36 && bytes.length >= 2) {
      let state = active.get(canId);
      if (!state) {
        state = startOrphan(session, index);
        active.set(canId, state);
      }
      const counter = bytes[1];
      const data = Buffer.from(bytes.slice(2));
      const previous = state.blocks[state.blocks.length - 1];
      if (previous && counter === previous.counter) {
        const same = previous.data.equals(data);
        state.duplicateBlocks.push({ counter, identical: same, sessionIndex: index });
        if (!same) state.errors.push({ id: 'conflicting-duplicate-block', counter, sessionIndex: index });
        continue;
      }
      if (state.lastCounter != null) {
        const expected = (state.lastCounter + 1) & 0xff;
        if (counter !== expected) state.errors.push({ id: 'block-sequence-gap', expected, actual: counter, sessionIndex: index });
      }
      state.blocks.push({ counter, data, sessionIndex: index });
      state.lastCounter = counter;
      continue;
    }

    if (sid === 0x37) {
      const state = active.get(canId);
      if (!state) continue;
      transfers.push(finalize(state, true, index));
      active.delete(canId);
      programmingSeen.set(canId, false);
    }
  }

  for (const state of active.values()) transfers.push(finalize(state, false, sessions.length - 1));
  return {
    transfers,
    completeTransfers: transfers.filter((item) => item.complete).length,
    exportableTransfers: transfers.filter((item) => item.artifactReady).length,
    firmwareCandidates: transfers.filter((item) => item.firmwareSize > 0).map((item, index) => ({
      index,
      canId: item.canId,
      size: item.firmwareSize,
      sha256: item.firmwareSha256,
      confidence: item.confidence,
      address: item.requestDownload?.address || null,
      artifactReady: item.artifactReady
    })),
    hints: [
      '按 RequestDownload(0x34) → TransferData(0x36) → RequestTransferExit(0x37) 重建候选固件；仅处理完整 ISO-TP 请求负载。',
      '只有收到 0x37、blockSequenceCounter 无 gap/冲突且声明长度不矛盾时才生成可保存 artifact。',
      'blockMap 保留每个 TransferData block 的 BSC、sessionIndex、输出 offset 与长度，可用于回查抓包和定位缺口。',
      'dataFormatIdentifier 非 0 时导出的是 raw transfer payload，可能仍压缩/加密，不能直接当明文 ECU firmware。'
    ]
  };
}

module.exports = { reconstructUdsProgramming, parseRequestDownload, bytesFromSession };
