#!/usr/bin/env node
const crypto = require('crypto');

function seeded(seed) {
  let x = parseInt(crypto.createHash('sha256').update(String(seed)).digest('hex').slice(0, 8), 16) >>> 0;
  return () => {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    return (x >>> 0) / 0x100000000;
  };
}
function pick(rng, values) { return values[Math.floor(rng() * values.length) % values.length]; }
function n(rng, min, max) { return min + Math.floor(rng() * (max - min + 1)); }

const FAMILIES = [
  ['recon-port', 'recon', (r, positive) => positive
    ? `Nmap scan report for 10.13.${n(r,1,200)}.${n(r,2,250)}\n22/tcp open ssh OpenSSH_8.4\n80/tcp open http lighttpd\n554/tcp open rtsp\nSSID: ${pick(r,['Drone_AP','PX4_NET','CAM_LINK'])} WPA2`
    : `Nmap scan report for 10.13.1.20\nAll 1000 scanned ports are filtered\nSSID: LAB_NET WPA2`],
  ['spoof-gps', 'spoof', (r, positive) => positive
    ? `GPS_RAW_INT satellites_visible=18 fix_type=3 lat=312300000 lon=1214700000\nGLOBAL_POSITION_INT lat=322300000 lon=1214700000\nposition jump detected 111000m in 1s`
    : `GPS_RAW_INT satellites_visible=18 fix_type=3 lat=312300000 lon=1214700000\nGLOBAL_POSITION_INT lat=312300020 lon=1214700030\ntrajectory continuous`],
  ['dos-prearm', 'dos', (r, positive) => positive
    ? `STATUSTEXT severity=3 PreArm: GPS 1: Bad fix\nCOMMAND_LONG command=400 target=1 result=DENIED\nHEARTBEAT armed=false\nFENCE_ENABLE changed 0 -> 1`
    : `STATUSTEXT severity=6 EKF2 IMU0 is using GPS\nCOMMAND_LONG command=400 target=1 result=ACCEPTED\nHEARTBEAT armed=true`],
  ['inject-gcs', 'inject', (r, positive) => positive
    ? `MAVLink stream sysid=255 compid=190 signed linkId=1\nMAVLink stream sysid=255 compid=190 unsigned source=10.0.0.${n(r,30,90)}\nCOMMAND_LONG command=176\nSET_MODE custom_mode=${n(r,3,6)}`
    : `MAVLink stream sysid=255 compid=190 signed linkId=1\nCOMMAND_LONG command=176\nSET_MODE custom_mode=4\nall control frames signed`],
  ['leak-ftp', 'leak', (r, positive) => positive
    ? `USER ${pick(r,['pilot','admin','operator'])}\nPASS ${pick(r,['drone123','uav2026','camera'])}\nRETR /logs/0008.BIN\nRTSP rtsp://10.0.0.2/live H264`
    : `SFTP subsystem enabled\nTLS session established\nRTSP authentication required`],
  ['firmware-layout', 'firmware', (_r, positive) => positive
    ? `firmware.bin\nuImage header at 0x200\nSquashFS at 0x120000\nrootfs contains /etc/init.d and /www\nbootloader u-boot`
    : `firmware.bin\nrandom high entropy container\nno known filesystem signature`]
];

function generateSuite({ seed = 'uav-generalization-v1', count = 8 } = {}) {
  const rng = seeded(seed);
  const cases = [];
  for (let i = 0; i < count; i += 1) {
    for (const [family, category, make] of FAMILIES) {
      const positive = i % 2 === 0;
      cases.push({
        id: `${family}-${i}`,
        family,
        category,
        positive,
        input: make(rng, positive),
        expected: { category, shouldMatch: positive }
      });
    }
  }
  return { version: 1, seed: String(seed), countPerFamily: count, cases };
}

if (require.main === module) {
  const seedIndex = process.argv.indexOf('--seed');
  const countIndex = process.argv.indexOf('--count');
  const seed = seedIndex >= 0 ? process.argv[seedIndex + 1] : undefined;
  const count = countIndex >= 0 ? Number(process.argv[countIndex + 1]) : undefined;
  process.stdout.write(`${JSON.stringify(generateSuite({ seed, count }), null, 2)}\n`);
}

module.exports = { generateSuite, FAMILIES };
