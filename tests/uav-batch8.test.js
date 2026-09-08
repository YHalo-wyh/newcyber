const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const fsp=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const vm=require('node:vm');

const { parseWifiEvidence }=require('../src/core/uav_wifi');
const { analyzeFlightLog }=require('../src/core/uav_flight_log');
const { analyzeMavlinkControlFlow }=require('../src/core/uav_control_flow_v2');
const { analyzeUavChallengeEvidence }=require('../src/core/uav_challenge_matrix_v4');
const { scanWorkspace }=require('../src/core/finals_analyzer_batch8');

function mav1(msgid,payload,seq=1,sysid=255,compid=190) {
  return Buffer.concat([Buffer.from([0xfe,payload.length,seq,sysid,compid,msgid]),payload,Buffer.from([0,0])]);
}

function paramSet(name,value,target=1) {
  const p=Buffer.alloc(23,0);
  p.writeFloatLE(value,0); p[4]=target; p[5]=1;
  Buffer.from(name,'ascii').copy(p,6,0,16); p[22]=9;
  return p;
}

function paramValue(name,value) {
  const p=Buffer.alloc(25,0);
  p.writeFloatLE(value,0); p.writeUInt16LE(10,4); p.writeUInt16LE(1,6);
  Buffer.from(name,'ascii').copy(p,8,0,16); p[24]=9;
  return p;
}

function setMode(target=1,custom=4) {
  const p=Buffer.alloc(6,0); p.writeUInt32LE(custom,0); p[4]=target; p[5]=1; return p;
}

function attitude(timeMs,roll,pitch,yaw,rollSpeed=0,pitchSpeed=0,yawSpeed=0) {
  const p=Buffer.alloc(28,0);
  p.writeUInt32LE(timeMs,0); p.writeFloatLE(roll,4); p.writeFloatLE(pitch,8); p.writeFloatLE(yaw,12);
  p.writeFloatLE(rollSpeed,16); p.writeFloatLE(pitchSpeed,20); p.writeFloatLE(yawSpeed,24);
  return p;
}

test('Wi-Fi workbench reconstructs identity, offline auth material, Deauth and key candidate',()=>{
  const input=`BSSID: AA:BB:CC:DD:EE:FF  SSID: DroneNet  channel 6 WPA2\nWPA handshake: AA:BB:CC:DD:EE:FF\nDeauthentication reason code 7\nKEY FOUND! [ drone-pass-2026 ]`;
  const result=parseWifiEvidence(input);
  assert.equal(result.networks[0].bssid,'aa:bb:cc:dd:ee:ff');
  assert.match(result.networks[0].ssid,/DroneNet/);
  assert.ok(result.handshakes.some((x)=>x.id==='wpa-handshake'));
  assert.equal(result.deauth.length,1);
  assert.equal(result.crackResults[0].candidate,'drone-pass-2026');
  assert.ok(result.findings.some((x)=>x.id==='wifi-key-candidate'));
});

test('DataFlash text log uses FMT definitions to extract GPS, attitude, parameter and event timeline',()=>{
  const text=[
    'FMT, 128, 24, ATT, Iffffff, TimeMS,Roll,Pitch,Yaw,RollSpeed,PitchSpeed,YawSpeed',
    'FMT, 129, 20, GPS, Iff, TimeMS,Lat,Lng',
    'FMT, 130, 20, PARM, Nf, Name,Value',
    'FMT, 131, 20, ERR, IN, TimeMS,Message',
    'ATT, 1000, 0.1, 0.2, 0.3, 0.01, 0.02, 0.03',
    'GPS, 1100, 31.2304, 121.4737',
    'PARM, FENCE_ENABLE, 1',
    'ERR, 1200, GPS_FAIL'
  ].join('\n');
  const result=analyzeFlightLog(text);
  assert.equal(result.format,'ardupilot-dataflash-text');
  assert.equal(result.attitude.length,1);
  assert.equal(result.gps.length,1);
  assert.equal(result.params.length,1);
  assert.equal(result.events.length,1);
  assert.ok(result.findings.some((x)=>x.id==='flightlog-geofence-param'));
  assert.ok(result.timeRange.durationSec>=0.1);
});

test('geofence transaction requires matching PARAM_VALUE readback before claiming confirmed change',()=>{
  const wire=Buffer.concat([
    mav1(23,paramSet('FENCE_ENABLE',0),10,255,190),
    mav1(22,paramValue('FENCE_ENABLE',0),11,1,1)
  ]).toString('hex');
  const result=analyzeMavlinkControlFlow(wire);
  const tx=result.geofenceTransactions.find((x)=>x.paramId==='FENCE_ENABLE');
  assert.ok(tx);
  assert.equal(tx.confirmed,true);
  assert.ok(result.findings.some((x)=>x.id==='geofence-param-confirmed'));
  const matrix=analyzeUavChallengeEvidence(wire,{category:'dos'});
  const hit=matrix.hits.find((x)=>x.scenarioId==='geofence-change');
  assert.ok(hit);
  assert.ok(hit.confidence>=0.9);
});

test('GCS profiling detects competing controllers targeting the same aircraft without hard-coded sysid',()=>{
  const wire=Buffer.concat([
    mav1(11,setMode(1,4),1,255,190),
    mav1(11,setMode(1,6),2,42,77)
  ]).toString('hex');
  const result=analyzeMavlinkControlFlow(wire);
  assert.equal(result.gcsProfiles.length,2);
  assert.ok(result.findings.some((x)=>x.id==='gcs-competing-controller'));
  const matrix=analyzeUavChallengeEvidence(wire,{category:'inject'});
  assert.ok(matrix.hits.some((x)=>x.scenarioId==='gcs-spoof'));
});

test('batch8 wrapper preserves physical attitude-spoof detection',()=>{
  const wire=Buffer.concat([
    mav1(30,attitude(1000,0,0,0),1,1,1),
    mav1(30,attitude(1100,3.0,0,0,0.01,0,0),2,1,1)
  ]).toString('hex');
  const result=analyzeUavChallengeEvidence(wire,{category:'spoof'});
  assert.ok(result.telemetry?.anomalies?.some((x)=>x.id==='attitude-jump'));
  assert.ok(result.hits.some((x)=>x.scenarioId==='attitude-spoof'));
});

test('batch8 workspace auto-enriches Wi-Fi and DataFlash attachments',async()=>{
  const dir=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-uav8-'));
  try {
    await fsp.writeFile(path.join(dir,'wifi.log'),'SSID: DroneLab BSSID: 12:34:56:78:9a:bc channel 11 WPA2\nEAPOL 4-way handshake\n');
    await fsp.writeFile(path.join(dir,'flight.log'),'FMT, 129, 20, GPS, Iff, TimeMS,Lat,Lng\nGPS, 1000, 31.2, 121.4\n');
    const analysis=await scanWorkspace(dir);
    const wifi=analysis.files.find((x)=>x.path==='wifi.log');
    const flight=analysis.files.find((x)=>x.path==='flight.log');
    assert.ok(wifi?.metadata?.uavWifi);
    assert.equal(flight?.metadata?.uavFlightLog?.format,'ardupilot-dataflash-text');
    assert.ok(analysis.recommendations.some((x)=>/Batch 8/.test(x)));
  } finally { await fsp.rm(dir,{recursive:true,force:true}); }
});

test('batch8 UAV renderer compiles, loads before later extensions, and Electron uses Batch 8 or newer workspace',()=>{
  const root=path.join(__dirname,'..');
  const source=fs.readFileSync(path.join(root,'renderer/uav_batch8_tools.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  const main=fs.readFileSync(path.join(root,'main.js'),'utf8');
  assert.doesNotThrow(()=>new vm.Script(source,{filename:'renderer/uav_batch8_tools.js'}));
  assert.ok(html.indexOf('uav_batch8_tools.js')>html.indexOf('uav_challenge_tools.js'));
  assert.match(source,/Wi-Fi 破解 \/ 握手证据/);
  assert.match(source,/飞行日志提取 \/ 时间线/);
  assert.match(source,/地理围栏变更事务/);
  assert.match(source,/GCS 控制源画像/);
  assert.match(main,/finals_analyzer_batch(?:8|9|11)/);
});
