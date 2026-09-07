const path = require('path');
const { createBinaryArtifact } = require('./artifacts');

const MAX_REASSEMBLY_BYTES = 64 * 1024 * 1024;

function stateKey(sysid, compid, session) {
  return `${sysid ?? 'unknown'}:${compid ?? 'unknown'}:${session ?? 'unknown'}`;
}

function findGaps(present, expectedSize) {
  const gaps = [];
  let start = -1;
  for (let i = 0; i < expectedSize; i += 1) {
    if (!present[i]) {
      if (start < 0) start = i;
    } else if (start >= 0) {
      gaps.push({ start, end: i, length: i - start });
      start = -1;
    }
  }
  if (start >= 0) gaps.push({ start, end: expectedSize, length: expectedSize - start });
  return gaps;
}

function cleanFileName(remotePath, fallback) {
  const normalized = String(remotePath || '').replace(/\\/g, '/');
  const base = path.posix.basename(normalized);
  return base && base !== '.' && base !== '/' ? base : fallback;
}

function reconstructOne(state) {
  const chunks = [...state.chunks].filter((chunk) => chunk.data.length > 0).sort((a, b) => a.offset - b.offset || a.frameIndex - b.frameIndex);
  const maxEnd = chunks.reduce((max, chunk) => Math.max(max, chunk.offset + chunk.data.length), 0);
  const expectedSize = Number.isInteger(state.expectedSize) ? state.expectedSize : (state.eofSeen ? maxEnd : null);
  const errors = [...state.errors];

  if (maxEnd > MAX_REASSEMBLY_BYTES || (expectedSize != null && expectedSize > MAX_REASSEMBLY_BYTES)) {
    errors.push({ id: 'reassembly-size-limit', maxEnd, expectedSize, limit: MAX_REASSEMBLY_BYTES });
    return {
      ...state,
      chunks: undefined,
      chunkMap: chunks.map((chunk) => ({ offset: chunk.offset, length: chunk.data.length, frameIndex: chunk.frameIndex, sequence: chunk.sequence })),
      expectedSize,
      reconstructedSize: 0,
      coveredBytes: 0,
      gaps: [],
      complete: false,
      artifact: null,
      errors
    };
  }

  const span = Math.max(maxEnd, expectedSize || 0);
  const buffer = Buffer.alloc(span);
  const present = new Uint8Array(span);
  let coveredBytes = 0;
  let duplicateBytes = 0;
  let conflictingBytes = 0;
  const conflicts = [];

  for (const chunk of chunks) {
    for (let i = 0; i < chunk.data.length; i += 1) {
      const target = chunk.offset + i;
      if (target >= span) continue;
      const value = chunk.data[i];
      if (!present[target]) {
        buffer[target] = value;
        present[target] = 1;
        coveredBytes += 1;
      } else if (buffer[target] === value) {
        duplicateBytes += 1;
      } else {
        conflictingBytes += 1;
        if (conflicts.length < 64) conflicts.push({ offset: target, existing: buffer[target], incoming: value, frameIndex: chunk.frameIndex });
      }
    }
  }

  if (conflictingBytes) errors.push({ id: 'conflicting-overlap', count: conflictingBytes, conflicts });
  if (expectedSize != null && maxEnd > expectedSize) errors.push({ id: 'chunk-beyond-declared-size', expectedSize, maxEnd });

  const targetSize = expectedSize != null ? expectedSize : maxEnd;
  const gaps = findGaps(present, targetSize);
  const complete = expectedSize != null && !errors.length && gaps.length === 0 && coveredBytes >= targetSize;
  const output = buffer.subarray(0, targetSize);
  const fallbackName = `mavftp-${state.remoteSystem || 'unknown'}-session-${state.session}.bin`;
  const artifact = complete ? createBinaryArtifact({
    name: cleanFileName(state.path, fallbackName),
    buffer: output,
    completeness: 'complete',
    provenance: chunks.map((chunk) => ({
      source: 'MAVLink FILE_TRANSFER_PROTOCOL',
      frameIndex: chunk.frameIndex,
      ftpSequence: chunk.sequence,
      session: state.session,
      offset: chunk.offset,
      length: chunk.data.length
    })),
    metadata: {
      kind: 'mavlink-ftp-file',
      remotePath: state.path || null,
      remoteSystem: state.remoteSystem,
      remoteComponent: state.remoteComponent,
      session: state.session,
      expectedSize,
      eofSeen: state.eofSeen
    }
  }) : null;

  return {
    remoteSystem: state.remoteSystem,
    remoteComponent: state.remoteComponent,
    session: state.session,
    path: state.path,
    openRequestFrameIndex: state.openRequestFrameIndex,
    openAckFrameIndex: state.openAckFrameIndex,
    expectedSize,
    eofSeen: state.eofSeen,
    chunkCount: chunks.length,
    chunkMap: chunks.map((chunk) => ({
      offset: chunk.offset,
      length: chunk.data.length,
      frameIndex: chunk.frameIndex,
      sequence: chunk.sequence,
      endOffset: chunk.offset + chunk.data.length
    })),
    reconstructedSize: output.length,
    coveredBytes,
    duplicateBytes,
    conflictingBytes,
    gaps,
    complete,
    errors,
    artifact
  };
}

function reconstructMavFtpFiles(events) {
  const items = Array.isArray(events) ? events : [];
  const pendingOpen = [];
  const states = new Map();

  const ensureState = (event, pending = null) => {
    const key = stateKey(event.sysid, event.compid, event.session);
    if (!states.has(key)) states.set(key, {
      remoteSystem: event.sysid,
      remoteComponent: event.compid,
      session: event.session,
      path: pending?.path || null,
      openRequestFrameIndex: pending?.frameIndex || null,
      openAckFrameIndex: null,
      expectedSize: null,
      eofSeen: false,
      chunks: [],
      errors: []
    });
    const state = states.get(key);
    if (!state.path && pending?.path) state.path = pending.path;
    if (!state.openRequestFrameIndex && pending?.frameIndex) state.openRequestFrameIndex = pending.frameIndex;
    return state;
  };

  for (const event of items) {
    if (!event) continue;

    if (event.opcode === 4 && event.path) {
      pendingOpen.push({
        targetSystem: event.targetSystem,
        targetComponent: event.targetComponent,
        sequence: event.sequence,
        path: event.path,
        frameIndex: event.frameIndex
      });
      if (pendingOpen.length > 128) pendingOpen.shift();
      continue;
    }

    if (event.opcode === 128 && event.reqOpcode === 4) {
      const exactIndex = pendingOpen.findIndex((item) => item.targetSystem === event.sysid && item.sequence === event.sequence);
      let pending = exactIndex >= 0 ? pendingOpen.splice(exactIndex, 1)[0] : null;
      if (!pending) {
        for (let i = pendingOpen.length - 1; i >= 0; i -= 1) {
          if (pendingOpen[i].targetSystem === event.sysid) {
            pending = pendingOpen.splice(i, 1)[0];
            break;
          }
        }
      }
      const state = ensureState(event, pending);
      state.openAckFrameIndex = event.frameIndex;
      if (Number.isInteger(event.openedFileSize)) state.expectedSize = event.openedFileSize;
      continue;
    }

    if (event.fileChunk?.dataHex) {
      const state = ensureState(event);
      const data = Buffer.from(event.fileChunk.dataHex, 'hex');
      if (data.length) state.chunks.push({
        offset: Number(event.fileChunk.offset ?? event.offset ?? 0),
        data,
        frameIndex: event.frameIndex,
        sequence: event.sequence
      });
      continue;
    }

    if (event.opcode === 129 && [5, 15].includes(event.reqOpcode) && event.errorName === 'EOF') {
      const state = ensureState(event);
      state.eofSeen = true;
      continue;
    }

    if (event.opcode === 1 && event.session != null) {
      for (const state of states.values()) {
        if (state.session === event.session && state.remoteSystem === event.targetSystem) state.terminatedFrameIndex = event.frameIndex;
      }
    }
  }

  const files = [...states.values()].map(reconstructOne).sort((a, b) => (a.openRequestFrameIndex || 0) - (b.openRequestFrameIndex || 0));
  return {
    files,
    completeFiles: files.filter((file) => file.complete).length,
    exportableFiles: files.filter((file) => file.artifact).length,
    hints: [
      '按 OpenFileRO 请求与 ACK session 建立文件上下文，再用 ReadFile/BurstReadFile ACK 的 offset 重组数据。',
      '相同 offset 的相同字节视为重传；不同字节视为冲突。存在 gap/冲突时只保留 chunkMap，不生成可导出 artifact。',
      '完整性依据 openedFileSize，或在没有 size 时依据明确 EOF；仅看到若干 ReadFile 数据不等于拿到了完整文件。',
      `单文件重组上限 ${MAX_REASSEMBLY_BYTES} bytes，防止异常 offset 导致内存膨胀。`
    ]
  };
}

module.exports = { reconstructMavFtpFiles, MAX_REASSEMBLY_BYTES };
