const fs = require('fs/promises');
const path = require('path');
const { bufferFromArtifact, sanitizeName } = require('./artifacts');

function stemFromSource(sourceName = 'firmware.bin') {
  const safe = sanitizeName(sourceName, 'firmware.bin');
  return path.parse(safe).name || 'firmware';
}

async function createUniqueDirectory(parentDir, baseName) {
  const parent = path.resolve(String(parentDir || ''));
  const safeBase = sanitizeName(baseName, 'firmware-recovered').replace(/\.[^.]+$/, '') || 'firmware-recovered';
  for (let index = 0; index < 1000; index += 1) {
    const suffix = index ? `-${index + 1}` : '';
    const candidate = path.join(parent, `${safeBase}${suffix}`);
    try {
      await fs.mkdir(candidate, { recursive: false });
      return candidate;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
  }
  throw new Error('无法创建唯一的固件导出目录');
}

function uniqueFileName(name, used) {
  const safe = sanitizeName(name, 'artifact.bin');
  const parsed = path.parse(safe);
  let candidate = safe;
  let index = 2;
  while (used.has(candidate.toLowerCase())) {
    candidate = `${parsed.name}-${index}${parsed.ext}`;
    index += 1;
  }
  used.add(candidate.toLowerCase());
  return candidate;
}

async function exportVerifiedFirmwareArtifacts({ artifacts, parentDir, sourceName }) {
  if (!Array.isArray(artifacts) || !artifacts.length) throw new Error('没有可导出的完整恢复段');
  const exportDir = await createUniqueDirectory(parentDir, `${stemFromSource(sourceName)}-recovered`);
  const used = new Set(['newcyber-manifest.json']);
  const files = [];

  try {
    for (const artifact of artifacts) {
      const decoded = bufferFromArtifact(artifact, { requireComplete: true });
      const name = uniqueFileName(decoded.name, used);
      const target = path.join(exportDir, name);
      await fs.writeFile(target, decoded.buffer, { flag: 'wx' });
      files.push({
        name,
        size: decoded.buffer.length,
        sha256: decoded.sha256,
        mediaType: decoded.mediaType,
        provenance: Array.isArray(artifact.provenance) ? artifact.provenance : [],
        metadata: artifact.metadata && typeof artifact.metadata === 'object' ? artifact.metadata : {}
      });
    }

    const manifest = {
      version: 1,
      tool: 'NewCyber firmware recovery',
      source: sanitizeName(sourceName, 'firmware.bin'),
      count: files.length,
      files
    };
    const manifestPath = path.join(exportDir, 'newcyber-manifest.json');
    await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
    return { outputDir: exportDir, manifestPath, files };
  } catch (error) {
    await fs.rm(exportDir, { recursive: true, force: true });
    throw error;
  }
}

module.exports = {
  stemFromSource,
  createUniqueDirectory,
  exportVerifiedFirmwareArtifacts
};
