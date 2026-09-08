const zlib = require('zlib');
const { bufferFromArtifact, createBinaryArtifact } = require('./artifacts');
const { scoreBuffer, magicName, printableRatio } = require('./auto_decode');
const { extractSuspiciousEncodings, decodeSuspiciousEncoding } = require('./encoding_probe');
const { analyzeCaptureIntelligence, scanEmbeddedCaptures } = require('./capture_intelligence_v2');

const MAX_NODE_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_NODES = 24;
const MAX_DEPTH = 2;
const MAX_TEXT_BYTES = 768 * 1024;
const MAX_TEXT_CANDIDATES = 8;

function uniquePushArtifact(out, seen, artifact) {
  if (!artifact || artifact.completeness !== 'complete' || !artifact.sha256 || seen.has(artifact.sha256)) return false;
  seen.add(artifact.sha256);
  out.push(artifact);
  return true;
}

function compactCapture(result) {
  return {
    format: result.format,
    packetCount: result.packetCount,
    linkTypes: result.linkTypes,
    highlights: (result.highlights || []).slice(0, 16),
    findings: (result.findings || []).slice(0, 40),
    nextActions: (result.nextActions || []).slice(0, 16),
    credentials: (result.network?.credentials || []).slice(0, 24),
    rtspEndpoints: (result.network?.rtspEndpoints || []).slice(0, 24),
    mavlinkFrames: result.network?.mavlink?.parsedFrames || 0,
    canFrames: result.can?.parsedFrames || 0,
    video: result.video ? {
      sessions: (result.video.sessions || []).slice(0, 12).map((x) => ({
        codec: x.codec, ssrc: x.ssrc, payloadType: x.payloadType, frames: x.frames,
        completeNal: x.completeNal, gaps: (x.gaps || []).length, artifact: x.artifact || null
      })),
      artifacts: (result.video.artifacts || []).slice(0, 8)
    } : null
  };
}

function decodeSummary(source, result) {
  const best = result.flagHits?.[0] || result.bestCandidates?.[0] || null;
  if (!best) return null;
  return {
    sourceKind: source.kind,
    sourceOffset: source.index,
    sourcePreview: source.value.slice(0, 160),
    confidence: source.confidence,
    foundFlag: result.foundFlag || null,
    path: best.path || [],
    score: best.score || 0,
    magic: best.magic || null,
    preview: best.preview || '',
    size: best.size || 0,
    sha256: best.sha256 || null,
    artifact: best.artifact || null
  };
}

function keepDecode(item) {
  if (!item) return false;
  if (item.foundFlag || item.magic || item.artifact) return true;
  return item.score >= 230 && /(?:flag|ctf|key|secret|password|token|admin|success|accepted)/i.test(item.preview || '');
}

function makeDecompressedArtifact(buffer, parent, kind) {
  const ext = magicName(buffer)?.toLowerCase() || 'bin';
  return createBinaryArtifact({
    name: `${String(parent.name || 'artifact').replace(/\.[^.]+$/, '')}-${kind}.${ext}`,
    buffer,
    completeness: 'complete',
    provenance: [
      ...(Array.isArray(parent.provenance) ? parent.provenance : []),
      { source: 'recursive-artifact', transform: kind, parentSha256: parent.sha256 }
    ],
    metadata: { kind: 'recursive-decompressed', parentSha256: parent.sha256, transform: kind, magic: magicName(buffer) }
  });
}

function analyzeArtifactTree(seedArtifacts, options = {}) {
  const maxDepth = Math.max(1, Math.min(Number(options.maxDepth) || MAX_DEPTH, 3));
  const maxNodes = Math.max(1, Math.min(Number(options.maxNodes) || MAX_NODES, 64));
  const maxNodeBytes = Math.max(1024, Math.min(Number(options.maxNodeBytes) || MAX_NODE_BYTES, 32 * 1024 * 1024));
  const maxTotalBytes = Math.max(maxNodeBytes, Math.min(Number(options.maxTotalBytes) || MAX_TOTAL_BYTES, 96 * 1024 * 1024));
  const queue = [];
  const seenNodes = new Set();
  const artifactSeen = new Set();
  const artifacts = [];
  const nodes = [];
  const findings = [];
  const flags = [];
  let totalBytes = 0;
  let skippedOversize = 0;

  const enqueue = (artifact, depth, lineage) => {
    if (!artifact || artifact.completeness !== 'complete' || !artifact.sha256 || seenNodes.has(artifact.sha256)) return;
    if (artifact.size > maxNodeBytes) { skippedOversize += 1; return; }
    if (queue.length + seenNodes.size >= maxNodes * 2) return;
    queue.push({ artifact, depth, lineage });
    uniquePushArtifact(artifacts, artifactSeen, artifact);
  };

  for (const artifact of seedArtifacts || []) enqueue(artifact, 0, [artifact?.name || 'artifact']);

  while (queue.length && nodes.length < maxNodes) {
    const current = queue.shift();
    const artifact = current.artifact;
    if (seenNodes.has(artifact.sha256)) continue;
    if (current.depth > maxDepth) continue;
    let decoded;
    try { decoded = bufferFromArtifact(artifact, { requireComplete: true }); }
    catch (error) {
      nodes.push({ depth: current.depth, name: artifact.name, sha256: artifact.sha256, error: error.message, lineage: current.lineage });
      continue;
    }
    if (totalBytes + decoded.buffer.length > maxTotalBytes) { skippedOversize += 1; continue; }
    seenNodes.add(artifact.sha256);
    totalBytes += decoded.buffer.length;
    const buffer = decoded.buffer;
    const scored = scoreBuffer(buffer);
    const node = {
      depth: current.depth,
      name: artifact.name,
      sha256: artifact.sha256,
      size: artifact.size,
      magic: scored.magic || magicName(buffer),
      printableRatio: Number(printableRatio(buffer).toFixed(3)),
      lineage: current.lineage,
      flags: scored.flags || [],
      decode: null,
      capture: null,
      embeddedCaptures: 0,
      decompressed: []
    };
    for (const flag of node.flags) if (!flags.includes(flag)) flags.push(flag);

    if (['PCAP', 'PCAPNG'].includes(node.magic)) {
      try {
        const capture = analyzeCaptureIntelligence(buffer);
        if (capture.format !== 'unknown') {
          node.capture = compactCapture(capture);
          for (const finding of capture.findings || []) findings.push({
            ...finding,
            id: `recursive-capture:${artifact.sha256}:${finding.id}`,
            sourceArtifact: artifact.name,
            evidence: finding.evidence || `artifact=${artifact.name}`
          });
          for (const videoArtifact of capture.video?.artifacts || []) {
            uniquePushArtifact(artifacts, artifactSeen, videoArtifact);
            if (current.depth < maxDepth) enqueue(videoArtifact, current.depth + 1, [...current.lineage, videoArtifact.name]);
          }
        }
      } catch (error) { node.captureError = error.message; }
    } else if (buffer.length <= maxNodeBytes) {
      try {
        const embedded = scanEmbeddedCaptures(buffer, { maxCaptures: 8 });
        node.embeddedCaptures = embedded.length;
        for (const item of embedded.slice(0, 8)) {
          if (!item.artifact) continue;
          uniquePushArtifact(artifacts, artifactSeen, item.artifact);
          findings.push({
            id: `recursive-embedded-capture:${artifact.sha256}:${item.offset}`,
            severity: 'info',
            title: '递归产物中恢复嵌入式抓包',
            sourceArtifact: artifact.name,
            evidence: `${item.format || 'capture'} @ 0x${Number(item.offset || 0).toString(16)}`
          });
          if (current.depth < maxDepth) enqueue(item.artifact, current.depth + 1, [...current.lineage, item.artifact.name]);
        }
      } catch (error) { node.embeddedCaptureError = error.message; }
    }

    if (buffer.length <= MAX_TEXT_BYTES && printableRatio(buffer) >= 0.62) {
      const text = buffer.toString('utf8');
      const suspicious = extractSuspiciousEncodings(text, { limit: MAX_TEXT_CANDIDATES });
      const kept = [];
      for (const source of suspicious) {
        try {
          const result = decodeSuspiciousEncoding(source, { maxDepth: 2 });
          const summary = decodeSummary(source, result);
          if (!keepDecode(summary)) continue;
          kept.push(summary);
          if (summary.foundFlag && !flags.includes(summary.foundFlag)) flags.push(summary.foundFlag);
          if (summary.artifact) {
            uniquePushArtifact(artifacts, artifactSeen, summary.artifact);
            if (current.depth < maxDepth) enqueue(summary.artifact, current.depth + 1, [...current.lineage, summary.artifact.name]);
          }
        } catch {}
      }
      if (suspicious.length || kept.length) node.decode = { attempted: suspicious.length, candidates: kept.slice(0, 8) };
    }

    if (current.depth < maxDepth && buffer.length <= maxNodeBytes) {
      if (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) {
        try {
          const out = zlib.gunzipSync(buffer, { maxOutputLength: maxNodeBytes });
          const derived = makeDecompressedArtifact(out, artifact, 'gunzip');
          node.decompressed.push({ transform: 'gunzip', artifact: derived });
          uniquePushArtifact(artifacts, artifactSeen, derived);
          enqueue(derived, current.depth + 1, [...current.lineage, derived.name]);
        } catch (error) { node.gzipError = error.message; }
      } else if (buffer.length >= 2 && buffer[0] === 0x78) {
        try {
          const out = zlib.inflateSync(buffer, { maxOutputLength: maxNodeBytes });
          const derived = makeDecompressedArtifact(out, artifact, 'inflate');
          node.decompressed.push({ transform: 'inflate', artifact: derived });
          uniquePushArtifact(artifacts, artifactSeen, derived);
          enqueue(derived, current.depth + 1, [...current.lineage, derived.name]);
        } catch {}
      }
    }

    if (node.flags.length) findings.push({
      id: `recursive-raw-flag:${artifact.sha256}`,
      severity: 'high',
      title: '递归恢复产物直接包含 Flag 候选',
      sourceArtifact: artifact.name,
      evidence: node.flags.slice(0, 4).join(', ')
    });
    if (node.decode?.candidates?.some((x) => x.foundFlag)) findings.push({
      id: `recursive-decoded-flag:${artifact.sha256}`,
      severity: 'high',
      title: '递归产物中的疑似编码自动解出 Flag 候选',
      sourceArtifact: artifact.name,
      evidence: node.decode.candidates.filter((x) => x.foundFlag).slice(0, 4).map((x) => `${x.path.join(' → ')} => ${x.foundFlag}`).join(' | ')
    });
    nodes.push(node);
  }

  return {
    schema: 'newcyber.recursive-artifact.v1',
    maxDepth,
    stats: { seedArtifacts: (seedArtifacts || []).length, analyzedNodes: nodes.length, totalBytes, skippedOversize, artifacts: artifacts.length, flags: flags.length },
    flags,
    artifacts: artifacts.slice(0, 32),
    findings: findings.slice(0, 160),
    nodes
  };
}

module.exports = { analyzeArtifactTree, compactCapture, MAX_NODE_BYTES, MAX_TOTAL_BYTES, MAX_NODES, MAX_DEPTH };
