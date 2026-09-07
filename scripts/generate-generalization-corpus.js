#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { mavlinkCrcX25, COMMON_CRC_EXTRA } = require('../src/core/mavlink_crc');

function seedInt(value) {
  const hex = crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 8);
  return Number.parseInt(hex, 16) >>> 0;
}

function rngFromSeed(seed) {
  let state = seedInt(seed) || 0x6d2b79f5;
  return () => {
    state += 0x6d2b79f5;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick(rng, items) {
  return items[Math.floor(rng() * items.length) % items.length];
}

function integer(rng, min, max) {
  return min + Math.floor(rng() * (max - min + 1));
}

function ident(rng, prefix) {
  const suffix = Math.floor(rng() * 0xffffff).toString(36);
  return `${prefix}_${suffix}`;
}

function buildMavlink1Heartbeat({ seq, sysid, compid, corrupt = false }) {
  const payload = Buffer.alloc(9);
  payload.writeUInt32LE(0, 0);
  payload[4] = 2;
  payload[5] = 3;
  payload[6] = 0x80;
  payload[7] = 4;
  payload[8] = 3;
  const body = Buffer.concat([Buffer.from([payload.length, seq, sysid, compid, 0]), payload]);
  let crc = mavlinkCrcX25(body, COMMON_CRC_EXTRA[0]);
  if (corrupt) crc ^= 0x0100;
  const trailer = Buffer.alloc(2);
  trailer.writeUInt16LE(crc, 0);
  return Buffer.concat([Buffer.from([0xfe]), body, trailer]).toString('hex');
}

function generateWeb3Case(rng, index) {
  const iface = `I${ident(rng, 'Oracle').replace(/_/g, '')}`;
  const param = ident(rng, 'feed');
  const method = ident(rng, 'quote');
  const fn = ident(rng, 'settle');
  const packedFn = ident(rng, 'authorize');
  const a = ident(rng, 'left');
  const b = ident(rng, 'right');
  const positive = index % 2 === 0;
  const source = positive ? `
pragma solidity ^0.8.20;
interface ${iface} { function ${method}(uint256) external view returns (uint256); }
contract Vault${index} {
  function ${fn}(${iface} ${param}, uint256 amount) external {
    uint256 value = ${param}.${method}(amount);
    if (value > 0) payable(msg.sender).transfer(0);
  }
  function ${packedFn}(string calldata ${a}, bytes calldata ${b}) external pure returns (bytes32) {
    return keccak256(abi.encodePacked(${a}, ${b}));
  }
}
` : `
pragma solidity ^0.8.20;
interface ${iface} { function ${method}(uint256) external view returns (uint256); }
contract Vault${index} {
  ${iface} public immutable TRUSTED_FEED;
  constructor(${iface} trustedFeed) { TRUSTED_FEED = trustedFeed; }
  function ${fn}(${iface} ${param}, uint256 amount) external view returns (uint256) {
    require(${param} == TRUSTED_FEED, "trusted");
    return ${param}.${method}(amount);
  }
  function ${packedFn}(string calldata ${a}, bytes calldata ${b}) external pure returns (bytes32) {
    return keccak256(abi.encode(${a}, ${b}));
  }
}
`;
  return {
    id: `web3-${index}`,
    track: 'web3', family: 'interface-trust-and-abi', positive,
    extension: '.sol', input: source,
    expected: positive
      ? { findingIds: ['external-contract-trust-boundary', 'abi-packed-dynamic-collision'] }
      : { absentFindingIds: ['abi-packed-dynamic-collision'], maxExternalTrustSeverity: 'low' }
  };
}

function generateAiCase(rng, index) {
  const output = pick(rng, ['transcription', 'response_text', 'model_output']);
  const cmd = ident(rng, 'cmd');
  const positive = index % 2 === 0;
  const source = positive ? `
import subprocess
${output} = result["text"]
${cmd} = f"printf '%s' {${output}}"
subprocess.run(${cmd}, shell=True)
` : `
import subprocess
${output} = result["text"]
subprocess.run(["printf", "%s", ${output}], shell=False)
`;
  return {
    id: `ai-${index}`, track: 'ai', family: 'model-output-shell', positive,
    extension: '.py', input: source,
    expected: positive ? { findingIds: ['ai-output-shell-injection'] } : { absentFindingIds: ['ai-output-shell-injection'] }
  };
}

function generateVehicleCase(rng, index) {
  const req = integer(rng, 0x700, 0x7df);
  let resp = req + 8;
  if (resp > 0x7ff) resp = req - 8;
  const seed = crypto.createHash('sha256').update(`seed-${index}-${req}`).digest().subarray(0, 4);
  const key = Buffer.from(seed.map((byte) => byte ^ 0xa5));
  const line = (id, data) => `${id.toString(16).toUpperCase()}#${data.padEnd(16, '0')}`;
  const positive = index % 2 === 0;
  const lines = [
    line(req, '022701'),
    line(resp, `066701${seed.toString('hex')}`),
    line(req, `066702${key.toString('hex')}`),
    line(resp, positive ? '026702' : '037F2735')
  ];
  return {
    id: `vehicle-${index}`, track: 'vehicle', family: 'uds-security-access', positive,
    extension: '.log', input: lines.join('\n'),
    expected: { requestId: `0x${req.toString(16).toUpperCase()}`, seedHex: seed.toString('hex'), success: positive }
  };
}

function generateLowaltCase(rng, index) {
  const sysid = integer(rng, 1, 250);
  const compid = integer(rng, 1, 200);
  const seq = integer(rng, 0, 255);
  const positive = index % 2 === 0;
  return {
    id: `lowalt-${index}`, track: 'lowalt', family: 'mavlink-crc', positive,
    extension: '.hex',
    input: buildMavlink1Heartbeat({ seq, sysid, compid, corrupt: !positive }),
    expected: { sysid, compid, crcStatus: positive ? 'valid' : 'invalid' }
  };
}

function encryptAesCbc(key, iv, plain) {
  const cipher = crypto.createCipheriv(`aes-${key.length * 8}-cbc`, key, iv);
  return Buffer.concat([cipher.update(Buffer.from(plain, 'utf8')), cipher.final()]);
}

function generateCryptoCase(rng, index) {
  const key = crypto.createHash('sha256').update(`key-${index}-${rng()}`).digest().subarray(0, 16);
  const iv = crypto.createHash('sha256').update(`iv-${index}-${rng()}`).digest().subarray(0, 16);
  const flag = `flag{general_crypto_${index}}`;
  const ciphertext = encryptAesCbc(key, iv, flag);
  const keyName = ident(rng, 'secretKey');
  const ivName = ident(rng, 'initialVector');
  const ctName = ident(rng, 'encryptedData');
  const positive = index % 2 === 0;
  const source = positive ? `
const algorithm = "aes-128-cbc";
const ${keyName} = Buffer.from("${key.toString('hex')}", "hex");
const ${ivName} = Buffer.from("${iv.toString('base64')}", "base64");
const ${ctName} = Buffer.from("${ciphertext.toString('hex')}", "hex");
const key = ${keyName};
const iv = ${ivName};
const ciphertext = ${ctName};
` : `
const algorithm = "aes-128-cbc";
const key = Buffer.from("${key.toString('hex')}", "hex");
const ciphertext = Buffer.from("${ciphertext.toString('hex')}", "hex");
// IV intentionally absent: analyzer must not guess it.
`;
  return {
    id: `common-${index}`, track: 'common', family: 'context-crypto', positive,
    extension: '.js', input: source,
    expected: positive ? { flag } : { missing: 'iv/nonce', noDecrypt: true }
  };
}

function generateSuite(options = {}) {
  const seed = options.seed ?? 'newcyber-generalization-v1';
  const count = Number.isInteger(options.count) ? Math.max(2, Math.min(options.count, 64)) : 8;
  const rng = rngFromSeed(seed);
  const cases = [];
  for (let i = 0; i < count; i += 1) {
    cases.push(generateWeb3Case(rng, i));
    cases.push(generateAiCase(rng, i));
    cases.push(generateVehicleCase(rng, i));
    cases.push(generateLowaltCase(rng, i));
    cases.push(generateCryptoCase(rng, i));
  }
  return { version: 1, seed: String(seed), countPerTrack: count, cases };
}

function writeSuite(outDir, suite) {
  fs.mkdirSync(outDir, { recursive: true });
  const manifest = [];
  for (const item of suite.cases) {
    const dir = path.join(outDir, item.track, item.family);
    fs.mkdirSync(dir, { recursive: true });
    const filename = `${item.id}${item.extension || '.txt'}`;
    fs.writeFileSync(path.join(dir, filename), item.input, 'utf8');
    manifest.push({ ...item, input: undefined, path: path.relative(outDir, path.join(dir, filename)) });
  }
  fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify({ ...suite, cases: manifest }, null, 2));
}

function parseArgs(argv) {
  const out = { seed: 'newcyber-generalization-v1', count: 8, outDir: null };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === '--seed') out.seed = argv[++i];
    else if (argv[i] === '--count') out.count = Number(argv[++i]);
    else if (argv[i] === '--out') out.outDir = argv[++i];
  }
  return out;
}

if (require.main === module) {
  const args = parseArgs(process.argv);
  const suite = generateSuite({ seed: args.seed, count: args.count });
  if (args.outDir) {
    const outDir = path.resolve(args.outDir);
    writeSuite(outDir, suite);
    process.stdout.write(`${JSON.stringify({ outDir, cases: suite.cases.length, seed: suite.seed })}\n`);
  } else {
    process.stdout.write(`${JSON.stringify(suite, null, 2)}\n`);
  }
}

module.exports = {
  rngFromSeed,
  buildMavlink1Heartbeat,
  generateWeb3Case,
  generateAiCase,
  generateVehicleCase,
  generateLowaltCase,
  generateCryptoCase,
  generateSuite,
  writeSuite
};
