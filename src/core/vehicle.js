const { parseCanLine, decodeUds } = require('./toolbox');

function frameHex(frame) {
  return Buffer.from(frame.bytes || []).toString('hex');
}

function reassembleIsoTpFrames(framesInput) {
  const frames = (framesInput || []).map((frame, index) => ({
    ...frame,
    index: frame.index || index + 1,
    bytes: [...(frame.bytes || [])]
  }));
  const active = new Map();
  const sessions = [];

  const finish = (state, complete, extra = {}) => {
    const payload = state.data.slice(0, state.totalLength);
    const item = {
      canId: `0x${state.id}`,
      startFrameIndex: state.startFrameIndex,
      endFrameIndex: state.lastFrameIndex,
      frameCount: state.frameCount,
      totalLength: state.totalLength,
      collectedLength: state.data.length,
      complete,
      payload: Buffer.from(payload).toString('hex'),
      sequenceNumbers: state.sequenceNumbers,
      ...extra
    };
    if (complete && payload.length) {
      try { item.uds = decodeUdsAdvanced(Buffer.from(payload).toString('hex')); } catch { /* keep raw payload */ }
    }
    sessions.push(item);
  };

  for (const frame of frames) {
    const bytes = frame.bytes || [];
    if (!bytes.length) continue;
    const pciType = bytes[0] >> 4;
    const id = String(frame.id || '').toUpperCase();
    if (!id) continue;

    if (pciType === 0) {
      const length = bytes[0] & 0x0f;
      if (!length || length > bytes.length - 1) continue;
      const payload = bytes.slice(1, 1 + length);
      sessions.push({
        canId: `0x${id}`,
        startFrameIndex: frame.index,
        endFrameIndex: frame.index,
        frameCount: 1,
        totalLength: length,
        collectedLength: length,
        complete: true,
        payload: Buffer.from(payload).toString('hex'),
        sequenceNumbers: [],
        uds: decodeUdsAdvanced(Buffer.from(payload).toString('hex'))
      });
      continue;
    }

    if (pciType === 1 && bytes.length >= 3) {
      const totalLength = ((bytes[0] & 0x0f) << 8) | bytes[1];
      if (totalLength <= bytes.length - 2) continue;
      const previous = active.get(id);
      if (previous) finish(previous, false, { error: 'new-first-frame-before-completion' });
      const state = {
        id,
        totalLength,
        data: bytes.slice(2),
        startFrameIndex: frame.index,
        lastFrameIndex: frame.index,
        frameCount: 1,
        expectedSequence: 1,
        sequenceNumbers: []
      };
      active.set(id, state);
      if (state.data.length >= totalLength) {
        finish(state, true);
        active.delete(id);
      }
      continue;
    }

    if (pciType === 2) {
      const state = active.get(id);
      if (!state) continue;
      const sequence = bytes[0] & 0x0f;
      if (sequence !== state.expectedSequence) {
        state.lastFrameIndex = frame.index;
        finish(state, false, {
          error: 'sequence-mismatch',
          expectedSequence: state.expectedSequence,
          actualSequence: sequence
        });
        active.delete(id);
        continue;
      }
      state.sequenceNumbers.push(sequence);
      state.data.push(...bytes.slice(1));
      state.lastFrameIndex = frame.index;
      state.frameCount += 1;
      state.expectedSequence = (state.expectedSequence + 1) & 0x0f;
      if (state.data.length >= state.totalLength) {
        finish(state, true);
        active.delete(id);
      }
    }
  }

  for (const state of active.values()) finish(state, false, { error: 'capture-ended-before-completion' });
  return sessions;
}

function reassembleIsoTp(text) {
  const frames = String(text || '').split(/\r?\n/).map(parseCanLine).filter(Boolean)
    .map((frame, index) => ({ ...frame, index: index + 1 }));
  return reassembleIsoTpFrames(frames);
}

function analyzeCanAdvanced(text) {
  const frames = String(text || '').split(/\r?\n/).map(parseCanLine).filter(Boolean);
  const groups = new Map();
  frames.forEach((frame, index) => {
    const enriched = { ...frame, index: index + 1, payload: frameHex(frame) };
    if (!groups.has(frame.id)) groups.set(frame.id, []);
    groups.get(frame.id).push(enriched);
  });

  const ids = [...groups.entries()].map(([id, list]) => {
    const maxDlc = Math.max(...list.map((frame) => frame.bytes.length), 0);
    const changingBytes = [];
    const counterCandidates = [];
    const transitions = [];

    for (let byteIndex = 0; byteIndex < maxDlc; byteIndex += 1) {
      const values = list.map((frame) => frame.bytes[byteIndex]).filter(Number.isInteger);
      if (new Set(values).size > 1) changingBytes.push(byteIndex);
      if (values.length >= 4) {
        let matches = 0;
        for (let i = 1; i < values.length; i += 1) {
          if (((values[i - 1] + 1) & 0xff) === values[i]) matches += 1;
        }
        if (matches / (values.length - 1) >= 0.75) counterCandidates.push(byteIndex);
      }
    }

    for (let i = 1; i < list.length; i += 1) {
      const before = list[i - 1];
      const after = list[i];
      const changes = [];
      const length = Math.max(before.bytes.length, after.bytes.length);
      for (let byteIndex = 0; byteIndex < length; byteIndex += 1) {
        const from = before.bytes[byteIndex] ?? null;
        const to = after.bytes[byteIndex] ?? null;
        if (from !== to) {
          changes.push({
            byteIndex,
            from,
            to,
            xor: Number.isInteger(from) && Number.isInteger(to) ? from ^ to : null,
            setBits: Number.isInteger(from) && Number.isInteger(to) ? ((~from) & to & 0xff) : null,
            clearedBits: Number.isInteger(from) && Number.isInteger(to) ? (from & (~to) & 0xff) : null
          });
        }
      }
      if (changes.length) {
        transitions.push({
          frameIndex: after.index,
          timestamp: after.timestamp,
          previousPayload: before.payload,
          payload: after.payload,
          changes
        });
      }
    }

    const times = list.map((frame) => frame.timestamp).filter(Number.isFinite);
    let averageIntervalMs = null;
    if (times.length >= 2) {
      let sum = 0;
      for (let i = 1; i < times.length; i += 1) sum += times[i] - times[i - 1];
      averageIntervalMs = Number(((sum / (times.length - 1)) * 1000).toFixed(3));
    }

    return {
      id: `0x${id}`,
      count: list.length,
      dlc: [...new Set(list.map((frame) => frame.bytes.length))],
      changingBytes,
      counterCandidates,
      averageIntervalMs,
      firstPayload: list[0]?.payload || '',
      lastPayload: list[list.length - 1]?.payload || '',
      transitions: transitions.slice(0, 300)
    };
  }).sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));

  const eventCandidates = ids.flatMap((item) => item.transitions.map((transition) => ({
    id: item.id,
    ...transition,
    score: transition.changes.reduce((score, change) => {
      const bitCount = Number.isInteger(change.xor) ? change.xor.toString(2).replace(/0/g, '').length : 8;
      return score + (bitCount <= 2 ? 2 : 1);
    }, 0)
  }))).sort((a, b) => b.score - a.score || a.frameIndex - b.frameIndex).slice(0, 100);

  const indexedFrames = frames.map((frame, index) => ({ ...frame, index: index + 1 }));
  const isoTpSessions = reassembleIsoTpFrames(indexedFrames);

  return {
    parsedFrames: frames.length,
    uniqueIds: ids.length,
    ids,
    eventCandidates,
    isoTpSessions,
    hints: [
      'transitions 会保留同一 CAN ID 的逐帧 byte/bit 跃迁，适合定位转向灯、车门、档位等首次状态变化。',
      'eventCandidates 只按“少量 bit 突变”启发式排序，不代表具体车辆语义。',
      'isoTpSessions 严格按 First Frame / Consecutive Frame sequence number 重组；序号不连续时保留错误而不是猜测数据。',
      '需要提交原始抓包帧 HEX 时，应回到对应 frameIndex 的原始 PCAP/SocketCAN frame 核对。'
    ]
  };
}

function decodeReadMemory(bytes, result) {
  if (bytes.length < 2) return result;
  const alfid = bytes[1];
  const addressLength = alfid & 0x0f;
  const sizeLength = alfid >> 4;
  const required = 2 + addressLength + sizeLength;
  if (!addressLength || !sizeLength || bytes.length < required) return result;
  const addressBytes = bytes.slice(2, 2 + addressLength);
  const sizeBytes = bytes.slice(2 + addressLength, required);
  const readBigInt = (arr) => arr.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);
  return {
    ...result,
    readMemory: {
      addressAndLengthFormatIdentifier: `0x${alfid.toString(16).padStart(2, '0')}`,
      addressLength,
      sizeLength,
      address: `0x${readBigInt(addressBytes).toString(16)}`,
      size: readBigInt(sizeBytes).toString(),
      sizeHex: `0x${Buffer.from(sizeBytes).toString('hex')}`
    }
  };
}

function decodeUdsAdvanced(input) {
  const raw = String(input || '').trim();
  const canMatch = raw.match(/^(?:0x)?[0-9a-fA-F]{3,8}#([0-9a-fA-F]+)$/);
  const udsInput = canMatch ? canMatch[1] : raw;
  const compact = udsInput.replace(/^0x/i, '').replace(/[^0-9a-f]/gi, '');
  if (!compact || compact.length % 2) return decodeUds(udsInput);
  let bytes = [...Buffer.from(compact, 'hex')];

  const pciType = bytes[0] >> 4;
  if (pciType === 0 && bytes.length >= 2) {
    const length = bytes[0] & 0x0f;
    bytes = bytes.slice(1, 1 + length);
  } else if (pciType === 1 && bytes.length >= 3) {
    bytes = bytes.slice(2);
  }

  let result = decodeUds(udsInput);
  const sid = bytes[0];
  const requestSid = sid >= 0x40 ? sid - 0x40 : sid;

  if (requestSid === 0x23 && sid < 0x40) result = decodeReadMemory(bytes, result);
  if (requestSid === 0x27 && bytes.length >= 2) {
    const subFunction = bytes[1];
    result.securityAccess = {
      ...(result.securityAccess || {}),
      subFunction,
      level: Math.ceil(subFunction / 2),
      meaning: subFunction % 2 ? 'requestSeed' : 'sendKey',
      seedOrKey: bytes.length > 2 ? `0x${Buffer.from(bytes.slice(2)).toString('hex')}` : null
    };
  }
  if (requestSid === 0x10 && bytes.length >= 2) {
    const sessions = { 0x01: 'defaultSession', 0x02: 'programmingSession', 0x03: 'extendedDiagnosticSession' };
    result.session = { subFunction: bytes[1], name: sessions[bytes[1]] || 'vendorSpecific/unknown' };
  }
  if (requestSid === 0x36 && bytes.length >= 2) {
    result.transferData = {
      blockSequenceCounter: bytes[1],
      dataLength: Math.max(bytes.length - 2, 0),
      data: Buffer.from(bytes.slice(2)).toString('hex')
    };
  }
  if (canMatch) result.can = { id: `0x${raw.split('#')[0].replace(/^0x/i, '').toUpperCase()}` };
  return result;
}

module.exports = { analyzeCanAdvanced, decodeUdsAdvanced, reassembleIsoTp, reassembleIsoTpFrames };
