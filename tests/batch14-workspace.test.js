const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const { scanWorkspace }=require('../src/core/finals_analyzer_batch14');

async function withWorkspace(fn) {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b14-'));
  try { await fn(dir); } finally { await fs.rm(dir,{recursive:true,force:true}); }
}

test('batch14 auto-routes GNSS, regulatory, update and AI transcript evidence',async()=>withWorkspace(async(dir)=>{
  await fs.writeFile(path.join(dir,'gps.nmea'),[
    '$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47',
    '$GPGGA,123520,5807.038,N,02131.000,E,1,08,0.9,545.4,M,46.9,M,,*46'
  ].join('\n'));
  await fs.writeFile(path.join(dir,'update.sh'),'wget http://update/fw.bin\nmd5sum fw.bin\nmtd write fw.bin firmware\nreboot\n');
  await fs.writeFile(path.join(dir,'api.py'),'@app.patch("/api/flight/permit/{flight_id}/approve")\ndef approve(flight_id):\n    body=request.json\n    status=body["status"]\n    save(status)\n');
  await fs.writeFile(path.join(dir,'transcript.csv'),'query,label,probabilities\na,0,"[0.99,0.01]"\nb,1,"[0.02,0.98]"\n');
  const fft=['frequency_hz,power_db'];
  for(let i=-20;i<=20;i+=1) fft.push(`${1575.42e6+i*250000},${i===0?-65:-92}`);
  await fs.writeFile(path.join(dir,'gnss_fft.csv'),fft.join('\n'));

  const analysis=await scanWorkspace(dir);
  assert.ok(analysis.version>=14);
  assert.ok(analysis.examDirectionCounts.gnss>=1);
  assert.ok(analysis.examDirectionCounts.gnssSpectrum>=1);
  assert.ok(analysis.examDirectionCounts.regulatory>=1);
  assert.ok(analysis.examDirectionCounts.update>=1);
  assert.ok(analysis.examDirectionCounts.extraction>=1);
  const byName=new Map(analysis.files.map((f)=>[f.path,f]));
  assert.ok(byName.get('gps.nmea').metadata.gnssAudit);
  assert.ok(byName.get('update.sh').metadata.firmwareUpdateAudit);
  assert.ok(byName.get('api.py').metadata.regulatoryAudit);
  assert.ok(byName.get('transcript.csv').metadata.modelExtractionAudit);
  assert.ok(byName.get('gnss_fft.csv').metadata.gnssSpectrumAudit);
}));
