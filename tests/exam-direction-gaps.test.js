const test=require('node:test');
const assert=require('node:assert/strict');

const { analyzeModelExtractionTranscript }=require('../src/core/ai_model_extraction');
const { analyzeModelInversion }=require('../src/core/ai_model_inversion');
const { scanRegulatoryApi }=require('../src/core/low_altitude_regulatory');
const { analyzeGnssLog }=require('../src/core/gnss_audit');
const { auditFirmwareUpdate }=require('../src/core/firmware_update_audit');
const { runTool }=require('../src/core/tool_router');

test('model extraction audit identifies soft-label and deterministic oracle exposure',()=>{
  const rows=[];
  for (let i=0;i<6;i+=1) rows.push({ query:`sample-${i%3}`, label:String(i%2), probabilities:i%2?[0.01234567,0.98765433]:[0.97654321,0.02345679] });
  const result=analyzeModelExtractionTranscript(rows);
  assert.equal(result.rows,6);
  assert.equal(result.uniqueQueries,3);
  assert.equal(result.duplicateQueries,3);
  assert.ok(result.probabilityRows>=6);
  assert.ok(result.findings.some((x)=>x.id==='extraction-full-probability-output'));
});

test('model inversion audit scores high-similarity reconstruction and output exposure',()=>{
  const result=analyzeModelInversion([
    { probabilities:[0.01,0.98,0.01], embedding:[0.2,0.3,0.4], reference:[0,1,0], reconstructed:[0.01,0.98,0.01] },
    { probabilities:[0.02,0.97,0.01], embedding:[0.21,0.31,0.41], reference:[1,0,0], reconstructed:[0.98,0.01,0.01] }
  ]);
  assert.equal(result.reconstructionPairs,2);
  assert.ok(result.findings.some((x)=>x.id==='inversion-embedding-exposure'));
  assert.ok(result.findings.some((x)=>x.id==='inversion-reconstruction-similarity'));
});

test('regulatory API audit flags object authorization and replay candidates',()=>{
  const source=`
POST /api/flight/permit/{flight_id}/approve
body = request.json
status = body.status
airspace_id = body.airspace_id
latitude = body.latitude
longitude = body.longitude
save(status, airspace_id, latitude, longitude)
`;
  const result=scanRegulatoryApi(source);
  assert.ok(result.surfaces['flight-permit']>=1);
  assert.ok(result.findings.some((x)=>x.id==='regulatory-object-authorization-candidate'));
  assert.ok(result.findings.some((x)=>x.id==='regulatory-replay-candidate'));
});

test('GNSS audit validates NMEA and finds impossible position jump',()=>{
  const input=[
    '$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47',
    '$GPGGA,123520,5807.038,N,02131.000,E,1,08,0.9,545.4,M,46.9,M,,*46'
  ].join('\n');
  const result=analyzeGnssLog(input,{maxSpeedMps:120});
  assert.equal(result.records,2);
  assert.ok(result.jumps.length>=1);
  assert.ok(result.findings.some((x)=>x.id==='gnss-position-physics-violation'));
});

test('firmware update audit reconstructs weak trust chain',()=>{
  const source=`
wget http://updates.local/fw.bin
md5sum fw.bin
mtd write fw.bin firmware
reboot
`;
  const result=auditFirmwareUpdate(source);
  assert.equal(result.stages.download,true);
  assert.equal(result.stages.flash,true);
  assert.equal(result.stages.signature,false);
  assert.ok(result.findings.some((x)=>x.id==='update-plain-http'));
  assert.ok(result.findings.some((x)=>x.id==='update-no-signature-evidence'));
});

test('tool router exposes the new analyzers',()=>{
  const extraction=runTool('ai-model-extraction',{input:JSON.stringify([{query:'x',label:'1',probabilities:[0.1,0.9]}])});
  assert.equal(extraction.rows,1);
  const update=runTool('firmware-update-audit',{input:'mtd write image.bin firmware'});
  assert.equal(update.stages.flash,true);
});
