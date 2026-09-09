'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  PINNED_ORT_VERSION,
  createRuntimeBundleManifest,
  verifyRuntimeBundle
} = require('../src/core/local_ml_runtime');

function parseArgs(argv) {
  const args = { verify: false, output: null };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--verify') args.verify = true;
    else if (value === '--output') args.output = argv[++index] || null;
    else throw new Error(`未知参数: ${value}`);
  }
  return args;
}

function runtimeRoot(output) {
  if (output) return path.resolve(output);
  return path.resolve(__dirname, '..', '.newcyber-runtime', `${process.platform}-${process.arch}`);
}

function npmExecutable() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

function prepare(root) {
  fs.mkdirSync(path.dirname(root), { recursive: true });
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });
  const args = [
    'install',
    '--prefix', root,
    '--no-save',
    '--omit=dev',
    '--no-audit',
    '--no-fund',
    '--onnxruntime-node-install=skip',
    `onnxruntime-node@${PINNED_ORT_VERSION}`
  ];
  const result = spawnSync(npmExecutable(), args, {
    stdio: 'inherit',
    shell: false,
    env: { ...process.env, npm_config_update_notifier: 'false' }
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`npm install 失败，exit=${result.status}`);
  const manifest = createRuntimeBundleManifest(root);
  fs.writeFileSync(path.join(root, 'newcyber-runtime.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  const verification = verifyRuntimeBundle(root);
  if (!verification.valid) throw new Error(`runtime bundle 校验失败: ${verification.error}`);
  return manifest;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = runtimeRoot(args.output);
  if (args.verify) {
    const result = verifyRuntimeBundle(root);
    process.stdout.write(`${JSON.stringify({ root, ...result, manifest: result.manifest ? { schema: result.manifest.schema, version: result.manifest.version, platform: result.manifest.platform, arch: result.manifest.arch, criticalFiles: result.manifest.criticalFiles.length } : null }, null, 2)}\n`);
    if (!result.valid) process.exitCode = 1;
    return;
  }
  const manifest = prepare(root);
  process.stdout.write(`\nNewCyber ONNX runtime bundle ready\n${root}\nonnxruntime-node ${manifest.version} · ${manifest.platform}/${manifest.arch}\n`);
  process.stdout.write('This preparation step may use the network. NewCyber runtime execution itself does not.\n');
}

try { main(); }
catch (error) {
  console.error(`[runtime:prepare] ${error?.stack || error}`);
  process.exitCode = 1;
}
