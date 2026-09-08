const test=require('node:test');
const assert=require('node:assert/strict');
const { analyzeGnssSpectrum }=require('../src/core/gnss_sdr');
const { runTool }=require('../src/core/tool_router');

function spectrumCsv() {
  const rows=['frequency_hz,power_db'];
  for (let i=-20;i<=20;i+=1) {
    const f=1575.42e6+i*250000;
    const p=i===0?-65:-92;
    rows.push(`${f},${p}`);
  }
  return rows.join('\n');
}

test('GNSS spectrum audit detects narrowband peak near L1',()=>{
  const result=analyzeGnssSpectrum(spectrumCsv());
  assert.ok(result.bands.some((x)=>x.id.includes('GPS-L1')));
  assert.ok(result.findings.some((x)=>x.id==='gnss-narrowband-interference-candidate'));
});

test('tool router exposes GNSS spectrum audit',()=>{
  const result=runTool('uav-gnss-spectrum',{input:spectrumCsv()});
  assert.ok(result.samples>10);
});
