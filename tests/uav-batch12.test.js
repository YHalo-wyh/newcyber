const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const os=require('os');
const path=require('path');
const { analyzeWifiCapture }=require('../src/core/uav_wifi_pcap');
const { parseUlog }=require('../src/core/uav_ulog');
const { scanWorkspace }=require('../src/core/finals_analyzer_batch12');

function macBytes(text){ return Buffer.from(text.replace(/:/g,''),'hex'); }
function dot11Header(fc,addr1,addr2,addr3){
  const b=Buffer.alloc(24); b.writeUInt16LE(fc,0); macBytes(addr1).copy(b,4); macBytes(addr2).copy(b,10); macBytes(addr3).copy(b,16); return b;
}
function beacon(){
  const bssid='02:11:22:33:44:55';
  const hdr=dot11Header(0x0080,'ff:ff:ff:ff:ff:ff',bssid,bssid);
  const fixed=Buffer.alloc(12);
  const ssid=Buffer.concat([Buffer.from([0,7]),Buffer.from('TestNet')]);
  const channel=Buffer.from([3,1,6]);
  const rsn=Buffer.from('30120100000fac040100000fac040100000fac02','hex');
  return Buffer.concat([hdr,fixed,ssid,channel,rsn]);
}
function eapolM1(){
  const ap='02:11:22:33:44:55', sta='02:aa:bb:cc:dd:ee';
  const hdr=dot11Header(0x0008,sta,ap,ap);
  const llc=Buffer.from('aaaa03000000888e','hex');
  const e=Buffer.alloc(99); e[0]=2; e[1]=3; e.writeUInt16BE(95,2); e[4]=2; e.writeUInt16BE(0x0088,5);
  return Buffer.concat([hdr,llc,e]);
}
function deauth(){
  const ap='02:11:22:33:44:55', sta='02:aa:bb:cc:dd:ee';
  const hdr=dot11Header(0x00c0,sta,ap,ap); const reason=Buffer.alloc(2); reason.writeUInt16LE(7); return Buffer.concat([hdr,reason]);
}
function classicPcap(frames){
  const gh=Buffer.alloc(24); Buffer.from('d4c3b2a1','hex').copy(gh,0); gh.writeUInt16LE(2,4); gh.writeUInt16LE(4,6); gh.writeUInt32LE(65535,16); gh.writeUInt32LE(105,20);
  const parts=[gh];
  frames.forEach((frame,i)=>{ const h=Buffer.alloc(16); h.writeUInt32LE(1700000000+i,0); h.writeUInt32LE(1000*i,4); h.writeUInt32LE(frame.length,8); h.writeUInt32LE(frame.length,12); parts.push(h,frame); });
  return Buffer.concat(parts);
}

function ulogMessage(type,payload){ const h=Buffer.alloc(3); h.writeUInt16LE(payload.length,0); h[2]=type.charCodeAt(0); return Buffer.concat([h,payload]); }
function addLogged(id,name){ const p=Buffer.alloc(3+Buffer.byteLength(name)); p[0]=0; p.writeUInt16LE(id,1); p.write(name,3); return ulogMessage('A',p); }
function gpsData(id,timestamp,lat,lon){
  const p=Buffer.alloc(2+26); p.writeUInt16LE(id,0); let o=2; p.writeBigUInt64LE(BigInt(timestamp),o);o+=8; p.writeInt32LE(lat,o);o+=4; p.writeInt32LE(lon,o);o+=4; p.writeInt32LE(100000,o);o+=4; p.writeFloatLE(10,o);o+=4; p[o++]=3;p[o++]=12; return ulogMessage('D',p);
}
function statusData(id,timestamp,nav,arming){ const p=Buffer.alloc(2+10); p.writeUInt16LE(id,0); p.writeBigUInt64LE(BigInt(timestamp),2); p[10]=nav; p[11]=arming; return ulogMessage('D',p); }
function buildUlog(){
  const header=Buffer.alloc(16); Buffer.from([0x55,0x4c,0x6f,0x67,0x01,0x12,0x35]).copy(header); header[7]=1; header.writeBigUInt64LE(1000000n,8);
  const fGps=ulogMessage('F',Buffer.from('vehicle_gps_position:uint64_t timestamp;int32_t lat;int32_t lon;int32_t alt;float vel_m_s;uint8_t fix_type;uint8_t satellites_used;'));
  const fStatus=ulogMessage('F',Buffer.from('vehicle_status:uint64_t timestamp;uint8_t nav_state;uint8_t arming_state;'));
  const dropout=Buffer.alloc(2); dropout.writeUInt16LE(250);
  return Buffer.concat([header,fGps,fStatus,addLogged(10,'vehicle_gps_position'),addLogged(11,'vehicle_status'),gpsData(10,1000000,250000000,550000000),statusData(11,1000000,2,1),gpsData(10,2000000,260000000,560000000),statusData(11,2000000,4,2),ulogMessage('O',dropout)]);
}

test('raw 802.11 PCAP recovers AP, WPA2 EAPOL and deauth evidence',()=>{
  const result=analyzeWifiCapture(classicPcap([beacon(),eapolM1(),deauth()]));
  assert.equal(result.format,'PCAP');
  assert.equal(result.supported,true);
  assert.equal(result.networks[0].ssid,'TestNet');
  assert.equal(result.networks[0].security,'WPA2-PSK');
  assert.equal(result.handshakes[0].message,1);
  assert.equal(result.deauth.length,1);
  assert.ok(result.findings.some((x)=>x.id==='wifi-eapol-handshake'));
  assert.ok(result.findings.some((x)=>x.id==='wifi-deauth-evidence'));
});

test('PX4 ULog parser uses F/A/D definitions and restores topic state',()=>{
  const result=parseUlog(buildUlog());
  assert.equal(result.format,'px4-ulog');
  assert.ok(result.topics.some((x)=>x.name==='vehicle_gps_position'));
  assert.equal(result.gps.length,2);
  assert.equal(result.modes.length,2);
  assert.equal(result.dropouts[0].durationMs,250);
  assert.ok(result.findings.some((x)=>x.id==='ulog-gps-position-jump'));
});

test('Batch 12 workspace enriches raw PCAP and ULog and rebuilds investigation graph',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'newcyber-b12-'));
  try{
    fs.writeFileSync(path.join(dir,'wifi.pcap'),classicPcap([beacon(),eapolM1(),deauth()]));
    fs.writeFileSync(path.join(dir,'flight.ulg'),buildUlog());
    const result=await scanWorkspace(dir);
    const wifi=result.files.find((x)=>x.path==='wifi.pcap');
    const ulog=result.files.find((x)=>x.path==='flight.ulg');
    assert.equal(wifi.metadata.uavWifiCapture.networks[0].ssid,'TestNet');
    assert.ok(ulog.metadata.uavFlightLog.topics.some((x)=>x.name==='vehicle_status'));
    assert.ok(result.investigation.focus.some((x)=>/802\.11|ULog|Wi-Fi/i.test(x.title)||/wifi|ulog/i.test(x.findingId||'')));
    assert.ok(Number(result.version)>=12);
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
});
