const base = require('./uav_challenge_matrix');
const { analyzeTelemetryConsistency } = require('./uav_telemetry');

const ANOMALY_MAP = Object.freeze({
  'gps-position-jump': ['gps-spoof', 'gps-offset'],
  'gps-source-disagreement': ['gps-spoof', 'sensor-inject'],
  'attitude-jump': ['attitude-spoof', 'sensor-inject'],
  'battery-range-invalid': ['battery-spoof'],
  'battery-voltage-outlier': ['battery-spoof'],
  'sensor-health-mismatch': ['system-status-spoof', 'error-spoof'],
  'vfr-groundspeed-disagreement': ['vfrhud-spoof'],
  'vfr-altitude-disagreement': ['vfrhud-spoof']
});

function compactHex(input) {
  const text = String(input || '').trim();
  const compact = text.replace(/^0x/i, '').replace(/[^0-9a-f]/gi, '');
  return compact.length >= 16 && compact.length % 2 === 0 && /^(?:fe|fd)/i.test(compact) ? compact : null;
}

function analyzeUavChallengeEvidence(input, options = {}) {
  const result = base.analyzeUavChallengeEvidence(input, options);
  const hex = compactHex(input);
  if (!hex) return result;
  try {
    const telemetry = analyzeTelemetryConsistency(hex);
    result.telemetry = telemetry;
    const wantedCategory = options.category || null;
    for (const anomaly of telemetry.anomalies || []) {
      for (const scenarioId of ANOMALY_MAP[anomaly.id] || []) {
        const scenario = base.SCENARIOS.find((x) => x.id === scenarioId);
        if (!scenario || (wantedCategory && scenario.category !== wantedCategory)) continue;
        const confidence = anomaly.severity === 'high' ? 0.93 : 0.82;
        const existing = result.hits.find((x) => x.scenarioId === scenarioId);
        const evidence = [`telemetry:${anomaly.id}`, anomaly.evidence];
        if (existing) {
          existing.confidence = Math.max(existing.confidence, confidence);
          existing.evidence = [...new Set([...(existing.evidence || []), ...evidence])];
        } else {
          result.hits.push({ scenarioId, title: scenario.title, category: scenario.category, confidence, evidence, action: scenario.action });
        }
      }
    }
    result.hits.sort((a,b)=>b.confidence-a.confidence || a.title.localeCompare(b.title));
    for (const row of result.matrix || []) row.matched = result.hits.some((hit)=>hit.scenarioId===row.id);
    result.coverage.matched = (result.matrix || []).filter((x)=>x.matched).length;
  } catch (error) {
    result.telemetryError = error.message;
  }
  return result;
}

module.exports = { ...base, analyzeUavChallengeEvidence, analyzeTelemetryConsistency };
