'use strict';

const { spawn } = require('child_process');

const PROBE_SOURCE = [
  'import json,sys,platform',
  'r={"python":platform.python_version(),"torch":None,"cuda":False,"ok":False}',
  'try:',
  '    import torch',
  '    r["torch"]=torch.__version__',
  '    r["cuda"]=bool(torch.cuda.is_available())',
  '    r["deviceCount"]=int(torch.cuda.device_count())',
  '    if r["cuda"]:',
  '        r["device"]=torch.cuda.get_device_name(0)',
  '        r["capability"]=list(torch.cuda.get_device_capability(0))',
  '        r["cudaRuntime"]=str(getattr(torch.version,"cuda",None))',
  '        x=torch.randn(1024,1024,device="cuda")',
  '        y=float((x@x).sum().item())',
  '        r["gpuMatmulOk"]=bool(y==y)',
  '    r["ok"]=True',
  'except Exception as e:',
  '    r["error"]=str(e)',
  'print(json.dumps(r))'
].join('\n');

const PROBE_TIMEOUT_MS = 45000;

function candidatePythons() {
  const list = [];
  if (process.env.NEWCYBER_PYTHON) list.push(process.env.NEWCYBER_PYTHON);
  if (process.platform === 'win32') {
    list.push('D:\\python\\python.exe', 'D:\\python310\\python.exe', 'python3', 'python');
  } else {
    list.push('python3', 'python');
  }
  return [...new Set(list)];
}

function runProbe(python, timeoutMs = PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(python, ['-c', PROBE_SOURCE], { windowsHide: true });
    } catch (error) {
      resolve({ python, status: 'missing', error: error.message });
      return;
    }
    let out = '';
    let err = '';
    let settled = false;
    const finish = (value) => { if (!settled) { settled = true; clearTimeout(timer); resolve(value); } };
    const timer = setTimeout(() => { try { child.kill(); } catch {} finish({ python, status: 'timeout', error: `probe timed out after ${timeoutMs}ms` }); }, timeoutMs);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => finish({ python, status: 'missing', error: e.message }));
    child.on('close', (code) => {
      const line = out.trim().split(/\r?\n/).reverse().find((l) => l.trim().startsWith('{'));
      if (!line) return finish({ python, status: 'error', error: (err || out || 'no output').slice(0, 300) });
      try {
        const parsed = JSON.parse(line);
        finish({ python, status: code === 0 && parsed.ok ? 'ok' : 'error', ...parsed, stderr: err.slice(0, 300) || undefined });
      } catch (e) {
        finish({ python, status: 'error', error: `unparsable output: ${e.message}` });
      }
    });
  });
}

async function inspectLocalTorch(options = {}) {
  const candidates = candidatePythons();
  const tried = [];
  for (const python of candidates) {
    const result = await runProbe(python, Number(options.timeoutMs) || PROBE_TIMEOUT_MS);
    tried.push({ python: result.python, status: result.status, torch: result.torch || null, error: result.error || null });
    if (result.status === 'ok') {
      return {
        schema: 'newcyber.local-torch.v1',
        status: 'ok',
        runtime: result.cuda ? 'torch-cuda' : 'torch-cpu',
        python: result.python,
        pythonVersion: result.python_version || null,
        torch: result.torch,
        cuda: Boolean(result.cuda),
        cudaRuntime: result.cudaRuntime || null,
        device: result.device || null,
        deviceCount: result.deviceCount || 0,
        capability: result.capability || null,
        gpuMatmulOk: result.gpuMatmulOk ?? null,
        probed: tried
      };
    }
  }
  return { schema: 'newcyber.local-torch.v1', status: 'unavailable', runtime: null, cuda: false, tried, hint: 'NEWCYBER_PYTHON env var can point to a python with torch installed' };
}

module.exports = { inspectLocalTorch, candidatePythons, runProbe };
