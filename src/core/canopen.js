const OBJECT_DICTIONARY = new Map([
  [0x1000, 'Device Type'],
  [0x1008, 'Manufacturer Device Name'],
  [0x1009, 'Manufacturer Hardware Version'],
  [0x100a, 'Manufacturer Software Version']
]);

function cobInfo(idText) {
  const id = Number.parseInt(String(idText || ''), 16);
  if (!Number.isInteger(id)) return null;
  if (id >= 0x600 && id <= 0x67f) return { id, nodeId: id - 0x600, direction: 'client-to-server' };
  if (id >= 0x580 && id <= 0x5ff) return { id, nodeId: id - 0x580, direction: 'server-to-client' };
  return null;
}

function objectIndex(bytes) {
  if (!bytes || bytes.length < 4) return null;
  return bytes[1] | (bytes[2] << 8);
}

function objectName(index) {
  return OBJECT_DICTIONARY.get(index) || null;
}

function preview(bytes) {
  const buffer = Buffer.from(bytes || []);
  const trimmed = buffer.subarray(0, buffer.indexOf(0) >= 0 ? buffer.indexOf(0) : buffer.length);
  if (!trimmed.length) return '';
  const text = trimmed.toString('utf8');
  const printable = [...text].filter((ch) => ch === '\t' || ch === '\n' || (ch.codePointAt(0) >= 0x20 && ch.codePointAt(0) !== 0x7f)).length;
  return printable / Math.max([...text].length, 1) >= 0.8 ? text : '';
}

function describeValue(bytes) {
  const data = [...(bytes || [])];
  return {
    hex: Buffer.from(data).toString('hex'),
    ascii: preview(data)
  };
}

function expeditedLength(command) {
  const expedited = Boolean(command & 0x02);
  const sizeIndicated = Boolean(command & 0x01);
  if (!expedited) return null;
  if (!sizeIndicated) return 4;
  const unused = (command >> 2) & 0x03;
  return 4 - unused;
}

function analyzeCanopenSdoFrames(framesInput) {
  const frames = (framesInput || []).map((frame, index) => ({ ...frame, index: frame.index || index + 1 }));
  const events = [];
  const transfers = [];
  const activeUploads = new Map();
  const activeDownloads = new Map();

  const finishTransfer = (state, direction, complete, extra = {}) => {
    const data = state.data.slice(0, state.totalLength || state.data.length);
    transfers.push({
      nodeId: state.nodeId,
      direction,
      index: `0x${state.index.toString(16).padStart(4, '0')}`,
      subIndex: state.subIndex,
      objectName: objectName(state.index),
      totalLength: state.totalLength ?? data.length,
      collectedLength: state.data.length,
      complete,
      startFrameIndex: state.startFrameIndex,
      endFrameIndex: state.lastFrameIndex,
      value: describeValue(data),
      ...extra
    });
  };

  for (const frame of frames) {
    const info = cobInfo(frame.id);
    const bytes = frame.bytes || [];
    if (!info || bytes.length < 1) continue;
    const command = bytes[0];

    if (command === 0x80 && bytes.length >= 8) {
      const index = objectIndex(bytes);
      const abortCode = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
      events.push({
        frameIndex: frame.index,
        nodeId: info.nodeId,
        direction: info.direction,
        type: 'abort',
        index: `0x${index.toString(16).padStart(4, '0')}`,
        subIndex: bytes[3],
        objectName: objectName(index),
        abortCode: `0x${(abortCode >>> 0).toString(16).padStart(8, '0')}`
      });
      continue;
    }

    if (info.direction === 'client-to-server') {
      if (command === 0x40 && bytes.length >= 4) {
        const index = objectIndex(bytes);
        events.push({ frameIndex: frame.index, nodeId: info.nodeId, direction: info.direction, type: 'upload-request', index: `0x${index.toString(16).padStart(4, '0')}`, subIndex: bytes[3], objectName: objectName(index) });
        continue;
      }

      const downloadLength = new Map([[0x2f, 1], [0x2b, 2], [0x27, 3], [0x23, 4]]).get(command);
      if (downloadLength && bytes.length >= 4 + downloadLength) {
        const index = objectIndex(bytes);
        const data = bytes.slice(4, 4 + downloadLength);
        events.push({ frameIndex: frame.index, nodeId: info.nodeId, direction: info.direction, type: 'expedited-download', index: `0x${index.toString(16).padStart(4, '0')}`, subIndex: bytes[3], objectName: objectName(index), value: describeValue(data) });
        continue;
      }

      if ((command & 0xe3) === 0x21 && bytes.length >= 8) {
        const index = objectIndex(bytes);
        const totalLength = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
        activeDownloads.set(info.nodeId, { nodeId: info.nodeId, index, subIndex: bytes[3], totalLength: totalLength >>> 0, data: [], startFrameIndex: frame.index, lastFrameIndex: frame.index, expectedToggle: 0 });
        events.push({ frameIndex: frame.index, nodeId: info.nodeId, direction: info.direction, type: 'segmented-download-init', index: `0x${index.toString(16).padStart(4, '0')}`, subIndex: bytes[3], objectName: objectName(index), totalLength: totalLength >>> 0 });
        continue;
      }

      if ((command & 0xe0) === 0x00 && activeDownloads.has(info.nodeId)) {
        const state = activeDownloads.get(info.nodeId);
        const toggle = (command >> 4) & 1;
        const unused = (command >> 1) & 7;
        const complete = Boolean(command & 1);
        if (toggle !== state.expectedToggle) {
          state.lastFrameIndex = frame.index;
          finishTransfer(state, 'download', false, { error: 'toggle-mismatch', expectedToggle: state.expectedToggle, actualToggle: toggle });
          activeDownloads.delete(info.nodeId);
          continue;
        }
        state.data.push(...bytes.slice(1, Math.max(1, 8 - unused)));
        state.lastFrameIndex = frame.index;
        state.expectedToggle ^= 1;
        if (complete) {
          finishTransfer(state, 'download', true);
          activeDownloads.delete(info.nodeId);
        }
      }
      continue;
    }

    const uploadLength = expeditedLength(command);
    if ((command & 0xe0) === 0x40 && uploadLength !== null && bytes.length >= 4) {
      const index = objectIndex(bytes);
      const data = bytes.slice(4, 4 + uploadLength);
      events.push({ frameIndex: frame.index, nodeId: info.nodeId, direction: info.direction, type: 'expedited-upload', index: `0x${index.toString(16).padStart(4, '0')}`, subIndex: bytes[3], objectName: objectName(index), value: describeValue(data) });
      continue;
    }

    if (command === 0x41 && bytes.length >= 8) {
      const index = objectIndex(bytes);
      const totalLength = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
      activeUploads.set(info.nodeId, { nodeId: info.nodeId, index, subIndex: bytes[3], totalLength: totalLength >>> 0, data: [], startFrameIndex: frame.index, lastFrameIndex: frame.index, expectedToggle: 0 });
      events.push({ frameIndex: frame.index, nodeId: info.nodeId, direction: info.direction, type: 'segmented-upload-init', index: `0x${index.toString(16).padStart(4, '0')}`, subIndex: bytes[3], objectName: objectName(index), totalLength: totalLength >>> 0 });
      continue;
    }

    if ((command & 0xe0) === 0x00 && activeUploads.has(info.nodeId)) {
      const state = activeUploads.get(info.nodeId);
      const toggle = (command >> 4) & 1;
      const unused = (command >> 1) & 7;
      const complete = Boolean(command & 1);
      if (toggle !== state.expectedToggle) {
        state.lastFrameIndex = frame.index;
        finishTransfer(state, 'upload', false, { error: 'toggle-mismatch', expectedToggle: state.expectedToggle, actualToggle: toggle });
        activeUploads.delete(info.nodeId);
        continue;
      }
      state.data.push(...bytes.slice(1, Math.max(1, 8 - unused)));
      state.lastFrameIndex = frame.index;
      state.expectedToggle ^= 1;
      if (complete) {
        finishTransfer(state, 'upload', true);
        activeUploads.delete(info.nodeId);
      }
    }
  }

  for (const state of activeUploads.values()) finishTransfer(state, 'upload', false, { error: 'capture-ended-before-completion' });
  for (const state of activeDownloads.values()) finishTransfer(state, 'download', false, { error: 'capture-ended-before-completion' });

  const objectValues = [];
  for (const event of events) {
    if (!event.value) continue;
    objectValues.push({ nodeId: event.nodeId, index: event.index, subIndex: event.subIndex, objectName: event.objectName, direction: event.type.includes('download') ? 'download' : 'upload', value: event.value, frameIndex: event.frameIndex });
  }
  for (const transfer of transfers) {
    if (transfer.complete) objectValues.push({ nodeId: transfer.nodeId, index: transfer.index, subIndex: transfer.subIndex, objectName: transfer.objectName, direction: transfer.direction, value: transfer.value, frameIndex: transfer.endFrameIndex });
  }

  return {
    detected: events.length > 0 || transfers.length > 0,
    events,
    transfers,
    objectValues,
    hints: [
      '0x600+node / 0x580+node 是常见 CANopen SDO client/server COB-ID；0x40 常见为 upload/read request。',
      '0x1000/0x1008/0x1009/0x100A 分别常见为设备类型、设备名、硬件版本、软件版本。',
      'segmented transfer 已按 toggle、unused-byte 与 complete 位重组；对象字典语义仍需结合具体设备 EDS/源码确认。'
    ]
  };
}

module.exports = { analyzeCanopenSdoFrames, OBJECT_DICTIONARY };
