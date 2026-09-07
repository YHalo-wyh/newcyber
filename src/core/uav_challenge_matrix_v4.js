const base = require('./uav_challenge_matrix_v3');
const { analyzeMavlinkControlFlow } = require('./uav_control_flow_v2');
const { parseWifiEvidence } = require('./uav_wifi');
const { analyzeFlightLog } = require('./uav_flight_log');

const CONTROL_MAP = Object.freeze({
  'geofence-param-confirmed':['geofence-change'],
  'geofence-param-mismatch':['geofence-change'],
  'gcs-signing-downgrade':['gcs-spoof','mavlink-inject'],
  'gcs-competing-controller':['gcs-spoof'],
  'gcs-identity-collision':['gcs-spoof']
});

function applyHit(result, scenarioId, confidence, evidence) {
  const scenario=base.SCENARIOS.find((x)=>x.id===scenarioId);
  if (!scenario) return;
  const existing=result.hits.find((x)=>x.scenarioId===scenarioId);
  if (existing) {
    existing.confidence=Math.max(existing.confidence,confidence);
    existing.evidence=[...new Set([...(existing.evidence||[]),...evidence.filter(Boolean)])];
  } else result.hits.push({ scenarioId, title:scenario.title, category:scenario.category, confidence, evidence:evidence.filter(Boolean), action:scenario.action });
}

function isMavHex(input) {
  const compact=String(input||'').trim().replace(/^0x/i,'').replace(/[^0-9a-f]/gi,'');
  return compact.length>=16 && compact.length%2===0 && /^(?:fe|fd)/i.test(compact);
}

function analyzeUavChallengeEvidence(input, options={}) {
  const result=base.analyzeUavChallengeEvidence(input,options);
  const category=options.category||null;

  if (isMavHex(input)) {
    try {
      const control=analyzeMavlinkControlFlow(input);
      result.controlFlow=control;
      for (const finding of control.findings||[]) {
        for (const scenarioId of CONTROL_MAP[finding.id]||[]) {
          const scenario=base.SCENARIOS.find((x)=>x.id===scenarioId);
          if (!scenario || (category && scenario.category!==category)) continue;
          const confidence=finding.severity==='high' ? 0.97 : 0.86;
          applyHit(result,scenarioId,confidence,[`control:${finding.id}`,finding.evidence]);
        }
      }
    } catch (error) { result.controlFlowV2Error=error.message; }
  } else {
    const wifi=parseWifiEvidence(input);
    if (wifi.networks.length || wifi.handshakes.length || wifi.deauth.length || wifi.crackResults.length) {
      result.wifi=wifi;
      if (!category || category==='recon') {
        if (wifi.handshakes.length || wifi.crackResults.length) applyHit(result,'wifi-cracking',wifi.crackResults.length?0.96:0.9,['wifi:offline-evidence',...wifi.handshakes.map((x)=>x.id)]);
      }
      if ((!category || category==='dos') && wifi.deauth.length) applyHit(result,'wifi-deauth',0.9,[`deauth-events=${wifi.deauth.length}`]);
    }

    const log=analyzeFlightLog(input);
    if (log.format!=='unknown') {
      result.flightLog=log;
      if (!category || category==='leak') applyHit(result,'flight-log-extract',0.94,[`log-format=${log.format}`,`gps=${log.gps?.length||0}`,`attitude=${log.attitude?.length||0}`]);
    }
  }

  result.hits.sort((a,b)=>b.confidence-a.confidence || a.title.localeCompare(b.title));
  for (const row of result.matrix||[]) row.matched=result.hits.some((hit)=>hit.scenarioId===row.id);
  if (result.coverage) result.coverage.matched=(result.matrix||[]).filter((x)=>x.matched).length;
  return result;
}

module.exports={ ...base, analyzeUavChallengeEvidence, analyzeMavlinkControlFlow, parseWifiEvidence, analyzeFlightLog };
