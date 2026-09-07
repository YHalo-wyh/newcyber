const base = require('./uav_challenge_matrix_v2');
const { analyzeMavlinkControlFlow } = require('./uav_control_flow');

const MAP = Object.freeze({
  'geofence-param-write': ['geofence-change'],
  'failsafe-param-write': ['prevent-takeoff'],
  'flight-termination-command': ['terminate-flight'],
  'home-position-command': ['home-overwrite'],
  'camera-gimbal-command': ['gimbal-takeover'],
  'mission-upload-observed': ['waypoint-inject'],
  'multiple-control-streams': ['gcs-spoof','mavlink-inject']
});

function mavHex(input) {
  const compact = String(input || '').trim().replace(/^0x/i,'').replace(/[^0-9a-f]/gi,'');
  return compact.length >= 16 && compact.length % 2 === 0 && /^(?:fe|fd)/i.test(compact) ? compact : null;
}

function analyzeUavChallengeEvidence(input, options = {}) {
  const result = base.analyzeUavChallengeEvidence(input, options);
  const hex = mavHex(input);
  if (!hex) return result;
  try {
    const control = analyzeMavlinkControlFlow(hex);
    result.controlFlow = control;
    for (const finding of control.findings || []) {
      for (const scenarioId of MAP[finding.id] || []) {
        const scenario = base.SCENARIOS.find((x)=>x.id===scenarioId);
        if (!scenario || (options.category && scenario.category !== options.category)) continue;
        const confidence = finding.severity === 'high' ? 0.96 : finding.severity === 'medium' ? 0.88 : 0.72;
        const hit = result.hits.find((x)=>x.scenarioId===scenarioId);
        const evidence = [`control:${finding.id}`, finding.evidence].filter(Boolean);
        if (hit) {
          hit.confidence = Math.max(hit.confidence, confidence);
          hit.evidence = [...new Set([...(hit.evidence || []), ...evidence])];
        } else result.hits.push({ scenarioId, title:scenario.title, category:scenario.category, confidence, evidence, action:scenario.action });
      }
    }
    result.hits.sort((a,b)=>b.confidence-a.confidence || a.title.localeCompare(b.title));
    for (const row of result.matrix || []) row.matched = result.hits.some((hit)=>hit.scenarioId===row.id);
    result.coverage.matched = (result.matrix || []).filter((x)=>x.matched).length;
  } catch (error) {
    result.controlFlowError = error.message;
  }
  return result;
}

module.exports = { ...base, analyzeUavChallengeEvidence, analyzeMavlinkControlFlow };
