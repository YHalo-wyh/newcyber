const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('zlib');
const { SCENARIOS, analyzeUavChallengeEvidence } = require('../src/core/uav_challenge_matrix');
const { analyzeFirmwareBuffer } = require('../src/core/firmware_unpack');
const { runTool } = require('../src/core/tool_router');

const EXPECTED = [
  'Wi-Fi 破解','端口侦查','数据嗅探','指纹识别','数据分析',
  '飞行姿态欺骗','GPS 欺骗','电池状态欺骗','错误状态欺骗','紧急状态欺骗','卫星信号欺骗','VFR_HUD 欺骗','系统状态欺骗',
  '更改地理围栏','Wi-Fi Deauth 攻击','GPS 偏移攻击','终止飞行攻击','视频流中断攻击','阻止起飞','链路层洪水攻击',
  '地面控制站欺骗','飞行模式注入','返航点覆盖','相机云台接管','传感器数据注入','机载计算机 Web 登录暴力破解','MAVLink 注入攻击','航路点注入','机载计算机接管',
  '飞行日志提取','参数提取','Wi-Fi 客户端数据泄露','FTP 窃听','摄像机信号窃听','固件攻击面'
];

test('UAV challenge catalog covers every supplied challenge idea', () => {
  const titles = new Set(SCENARIOS.map((x) => x.title));
  for (const title of EXPECTED) assert.equal(titles.has(title), true, title);
  assert.ok(SCENARIOS.length >= EXPECTED.length);
});

test('UAV recon analyzer turns nmap/wifi/rtsp evidence into ranked playbooks', () => {
  const input = `nmap scan\n22/tcp open ssh\n80/tcp open http\n554/tcp open rtsp\nSSID: Drone_AP WPA2\npacket capture pcapng`;
  const result = runTool('uav-recon-analyze', { input });
  assert.ok(result.hits.some((x) => x.scenarioId === 'port-recon'));
  assert.ok(result.hits.some((x) => x.scenarioId === 'wifi-cracking'));
  assert.ok(result.hits.some((x) => x.scenarioId === 'packet-sniffing'));
});

test('UAV leak analyzer recognizes FTP and camera stream evidence', () => {
  const result = analyzeUavChallengeEvidence('USER pilot\nPASS secret\nRETR /logs/001.BIN\nrtsp://10.0.0.2/live h264', { category:'leak' });
  assert.ok(result.hits.some((x) => x.scenarioId === 'ftp-sniff'));
  assert.ok(result.hits.some((x) => x.scenarioId === 'camera-signal-sniff'));
});

test('firmware analyzer recognizes and decodes embedded gzip stream', () => {
  const plain = Buffer.from('rootfs-test\nflag{firmware_pipeline}\n');
  const gz = zlib.gzipSync(plain);
  const fw = Buffer.concat([Buffer.alloc(0x80, 0x41), gz]);
  const result = analyzeFirmwareBuffer(fw);
  assert.ok(result.magic.some((x) => x.id === 'gzip'));
  const artifact = result.artifacts.find((x) => x.metadata?.kind === 'gzip-decoded');
  assert.ok(artifact);
  assert.equal(Buffer.from(artifact.hex, 'hex').toString('utf8'), plain.toString('utf8'));
});

test('firmware analyzer parses deterministic SquashFS size and carves exact artifact', () => {
  const rootfs = Buffer.alloc(128, 0);
  Buffer.from('hsqs').copy(rootfs, 0);
  rootfs.writeUInt32LE(3, 4);
  rootfs.writeUInt32LE(131072, 12);
  rootfs.writeBigUInt64LE(128n, 40);
  const fw = Buffer.concat([Buffer.alloc(32, 0xaa), rootfs, Buffer.from('TAIL')]);
  const result = analyzeFirmwareBuffer(fw, { tryDecompress:false });
  const structure = result.structures.find((x) => x.type === 'squashfs');
  assert.ok(structure);
  assert.equal(structure.offset, 32);
  assert.equal(structure.bytesUsed, 128);
  assert.equal(structure.artifact.size, 128);
});
