const test=require('node:test');
const assert=require('node:assert/strict');
const { analyzeVideoCapture,parseRtp }=require('../src/core/uav_video');
const { analyzeCaptureIntelligence }=require('../src/core/capture_intelligence_v2');

function ethernetUdp(payload,srcPort=5004,dstPort=5004) {
  const eth=Buffer.alloc(14,0); eth.writeUInt16BE(0x0800,12);
  const ip=Buffer.alloc(20,0); ip[0]=0x45; ip.writeUInt16BE(20+8+payload.length,2); ip[8]=64; ip[9]=17; ip.set([10,0,0,1],12); ip.set([10,0,0,2],16);
  const udp=Buffer.alloc(8,0); udp.writeUInt16BE(srcPort,0); udp.writeUInt16BE(dstPort,2); udp.writeUInt16BE(8+payload.length,4);
  return Buffer.concat([eth,ip,udp,payload]);
}

function rtp(seq,timestamp,payload,ssrc=0x12345678,marker=false) {
  const h=Buffer.alloc(12,0); h[0]=0x80; h[1]=(marker?0x80:0)|96; h.writeUInt16BE(seq,2); h.writeUInt32BE(timestamp,4); h.writeUInt32BE(ssrc,8);
  return Buffer.concat([h,payload]);
}

function pcap(packets) {
  const header=Buffer.alloc(24,0); header.writeUInt32LE(0xa1b2c3d4,0); header.writeUInt16LE(2,4); header.writeUInt16LE(4,6); header.writeUInt32LE(65535,16); header.writeUInt32LE(1,20);
  const records=[];
  packets.forEach((packet,i)=>{ const rh=Buffer.alloc(16,0); rh.writeUInt32LE(100+i,0); rh.writeUInt32LE(packet.length,8); rh.writeUInt32LE(packet.length,12); records.push(rh,packet); });
  return Buffer.concat([header,...records]);
}

test('RTP parser recognizes dynamic payload packet',()=>{
  const parsed=parseRtp(rtp(1,90000,Buffer.from([0x65,1,2,3])));
  assert.equal(parsed.sequence,1);
  assert.equal(parsed.payloadType,96);
  assert.equal(parsed.payload[0]&0x1f,5);
});

test('video analyzer reconstructs H264 single NAL and FU-A into Annex-B artifact',()=>{
  const packets=[
    {index:1,linkType:1,data:ethernetUdp(rtp(1,90000,Buffer.from([0x67,0x42,0x00,0x1e])))},
    {index:2,linkType:1,data:ethernetUdp(rtp(2,90000,Buffer.from([0x7c,0x85,0xaa,0xbb])))},
    {index:3,linkType:1,data:ethernetUdp(rtp(3,90000,Buffer.from([0x7c,0x45,0xcc,0xdd]),0x12345678,true))}
  ];
  const result=analyzeVideoCapture(packets);
  assert.equal(result.sessions.length,1);
  assert.equal(result.artifacts.length,1);
  assert.equal(result.artifacts[0].completeness,'complete');
  assert.match(result.artifacts[0].name,/\.h264$/);
  assert.ok(result.artifacts[0].hex.startsWith('0000000167'));
});

test('capture intelligence automatically includes video reconstruction',()=>{
  const capture=pcap([
    ethernetUdp(rtp(10,1000,Buffer.from([0x67,1,2,3]))),
    ethernetUdp(rtp(11,2000,Buffer.from([0x65,4,5,6]),0x12345678,true))
  ]);
  const result=analyzeCaptureIntelligence(capture);
  assert.equal(result.format,'PCAP');
  assert.equal(result.video.sessions.length,1);
  assert.equal(result.video.artifacts.length,1);
  assert.ok(result.highlights.some((x)=>/RTP\/H264/.test(x)));
});
