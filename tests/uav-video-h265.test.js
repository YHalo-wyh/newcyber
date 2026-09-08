const test=require('node:test');
const assert=require('node:assert/strict');
const { analyzeVideoCapture,h265Info }=require('../src/core/uav_video_v2');

function ethernetUdp(payload,srcPort=5006,dstPort=5006) {
  const eth=Buffer.alloc(14,0); eth.writeUInt16BE(0x0800,12);
  const ip=Buffer.alloc(20,0); ip[0]=0x45; ip.writeUInt16BE(20+8+payload.length,2); ip[8]=64; ip[9]=17; ip.set([10,0,0,1],12); ip.set([10,0,0,2],16);
  const udp=Buffer.alloc(8,0); udp.writeUInt16BE(srcPort,0); udp.writeUInt16BE(dstPort,2); udp.writeUInt16BE(8+payload.length,4);
  return Buffer.concat([eth,ip,udp,payload]);
}

function rtp(seq,timestamp,payload,ssrc=0xabcdef01,marker=false) {
  const h=Buffer.alloc(12,0); h[0]=0x80; h[1]=(marker?0x80:0)|98; h.writeUInt16BE(seq,2); h.writeUInt32BE(timestamp,4); h.writeUInt32BE(ssrc,8);
  return Buffer.concat([h,payload]);
}

test('H265 classifier recognizes VPS and FU',()=>{
  assert.equal(h265Info(Buffer.from([0x40,0x01,1,2])).nalType,32);
  const fu=h265Info(Buffer.from([0x62,0x01,0x93,1,2]));
  assert.equal(fu.type,'fu');
  assert.equal(fu.start,true);
  assert.equal(fu.fuType,19);
});

test('video analyzer reconstructs H265 Annex-B and suppresses same-key H264 guess',()=>{
  const packets=[
    {index:1,linkType:1,data:ethernetUdp(rtp(100,90000,Buffer.from([0x40,0x01,0x11,0x22])))},
    {index:2,linkType:1,data:ethernetUdp(rtp(101,93000,Buffer.from([0x62,0x01,0x93,0xaa,0xbb])))},
    {index:3,linkType:1,data:ethernetUdp(rtp(102,93000,Buffer.from([0x62,0x01,0x53,0xcc,0xdd]),0xabcdef01,true))}
  ];
  const result=analyzeVideoCapture(packets);
  assert.equal(result.sessions.length,1);
  assert.equal(result.sessions[0].codec,'H265');
  assert.equal(result.artifacts.length,1);
  assert.match(result.artifacts[0].name,/\.h265$/);
  assert.equal(result.artifacts[0].completeness,'complete');
  assert.ok(result.artifacts[0].hex.startsWith('000000014001'));
});
