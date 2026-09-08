const test=require('node:test');
const assert=require('node:assert/strict');
const { analyzeDatalinkCapture }=require('../src/core/uav_datalink');

function ethernetUdp(payload,srcPort,dstPort) {
  const eth=Buffer.alloc(14,0); eth.writeUInt16BE(0x0800,12);
  const ip=Buffer.alloc(20,0); ip[0]=0x45; ip.writeUInt16BE(20+8+payload.length,2); ip[8]=64; ip[9]=17; ip.set([10,0,0,1],12); ip.set([10,0,0,2],16);
  const udp=Buffer.alloc(8,0); udp.writeUInt16BE(srcPort,0); udp.writeUInt16BE(dstPort,2); udp.writeUInt16BE(8+payload.length,4);
  return Buffer.concat([eth,ip,udp,payload]);
}

function pcap(packets) {
  const header=Buffer.alloc(24,0); header.writeUInt32LE(0xa1b2c3d4,0); header.writeUInt16LE(2,4); header.writeUInt16LE(4,6); header.writeUInt32LE(65535,16); header.writeUInt32LE(1,20);
  const chunks=[header];
  packets.forEach((packet,i)=>{ const rh=Buffer.alloc(16,0); rh.writeUInt32LE(100+Math.floor(i/20),0); rh.writeUInt32LE((i%20)*50000,4); rh.writeUInt32LE(packet.length,8); rh.writeUInt32LE(packet.length,12); chunks.push(rh,packet); });
  return Buffer.concat(chunks);
}

test('datalink analyzer keeps explicit DJI/OcuSync evidence and pairs media/control flows',()=>{
  const packets=[];
  for(let i=0;i<40;i+=1) {
    const media=Buffer.alloc(1100,0x41);
    if(i===0) Buffer.from('DJI OcuSync session').copy(media,0);
    packets.push(ethernetUdp(media,7000,7001));
    packets.push(ethernetUdp(Buffer.alloc(120,0x22),7100,7101));
  }
  const result=analyzeDatalinkCapture(pcap(packets));
  assert.ok(result.vendorEvidence.some((x)=>x.vendor==='DJI'));
  assert.ok(result.vendorEvidence.some((x)=>x.vendor==='OcuSync'));
  assert.ok(result.pairedFlows.length>=1);
  assert.ok(result.findings.some((x)=>x.id==='uav-proprietary-link-fingerprint'));
});
