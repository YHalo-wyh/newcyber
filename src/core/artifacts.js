const crypto = require('crypto');
const path = require('path');

const MAX_ARTIFACT_BYTES = 128 * 1024 * 1024;

function sanitizeName(name, fallback = 'newcyber-artifact.bin') {
  const base = path.basename(String(name || fallback)).replace(/[\x00-\x1f<>:"/\\|?*]+/g, '_').trim();
  return base || fallback;
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function createBinaryArtifact({
  name,
  buffer,
  mediaType = 'application/octet-stream',
  completeness = 'complete',
  gaps = [],
  provenance = [],
  metadata = {}
}) {
  if (!Buffer.isBuffer(buffer)) throw new Error('artifact buffer 必须是 Buffer');
  if (buffer.length > MAX_ARTIFACT_BYTES) throw new Error(`artifact 超过 ${MAX_ARTIFACT_BYTES} bytes 上限`);
  return {
    version: 1,
    name: sanitizeName(name),
    mediaType,
    size: buffer.length,
    sha256: sha256(buffer),
    hex: buffer.toString('hex'),
    completeness,
    gaps: Array.isArray(gaps) ? gaps : [],
    provenance: Array.isArray(provenance) ? provenance : [],
    metadata: metadata && typeof metadata === 'object' ? metadata : {}
  };
}

function bufferFromArtifact(artifact, { requireComplete = false } = {}) {
  if (!artifact || artifact.version !== 1) throw new Error('不支持的 artifact 版本');
  if (requireComplete && artifact.completeness !== 'complete') throw new Error('拒绝保存非 complete artifact');
  const hex = String(artifact.hex || '');
  if (!/^[0-9a-f]*$/i.test(hex) || hex.length % 2) throw new Error('artifact hex 非法');
  const size = hex.length / 2;
  if (size > MAX_ARTIFACT_BYTES) throw new Error(`artifact 超过 ${MAX_ARTIFACT_BYTES} bytes 上限`);
  if (!Number.isInteger(artifact.size) || artifact.size !== size) throw new Error('artifact size 与 hex 不一致');
  const buffer = Buffer.from(hex, 'hex');
  const digest = sha256(buffer);
  if (!/^[0-9a-f]{64}$/i.test(String(artifact.sha256 || '')) || digest !== String(artifact.sha256).toLowerCase()) {
    throw new Error('artifact SHA-256 校验失败');
  }
  return { buffer, name: sanitizeName(artifact.name), sha256: digest, mediaType: artifact.mediaType || 'application/octet-stream' };
}

module.exports = {
  MAX_ARTIFACT_BYTES,
  sanitizeName,
  sha256,
  createBinaryArtifact,
  bufferFromArtifact
};
