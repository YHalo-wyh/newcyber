const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs/promises');
const os=require('os');
const path=require('path');
const { scanWorkspace }=require('../src/core/finals_analyzer_batch15');

async function workspace(fn) {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b15-'));
  try { await fn(dir); } finally { await fs.rm(dir,{recursive:true,force:true}); }
}

test('batch15 recognizes REST flight-permit source and OCR transcript automatically',async()=>workspace(async(dir)=>{
  await fs.writeFile(path.join(dir,'regulatory.py'),`@app.patch('/api/flight/permit/{flight_id}/approve')\ndef approve(flight_id):\n    body=request.json\n    status=body['status']\n    save(status)\n`);
  await fs.writeFile(path.join(dir,'ocr.json'),JSON.stringify([
    {image_id:'a',ocr_text:'HELLO',char_confidences:[0.99,0.98,0.97,0.96,0.95],boxes:[[1,2,30,10]]},
    {image_id:'b',ocr_text:'WORLD',char_confidences:[0.98,0.97,0.96,0.95,0.94],boxes:[[2,3,31,11]]}
  ]));
  const analysis=await scanWorkspace(dir);
  assert.ok(analysis.version>=15);
  const regulatory=analysis.files.find((f)=>f.path==='regulatory.py');
  const ocr=analysis.files.find((f)=>f.path==='ocr.json');
  assert.ok(regulatory.metadata.regulatoryAudit);
  assert.ok(regulatory.metadata.regulatoryAudit.surfaces['flight-permit']>=1);
  assert.ok(ocr.metadata.ocrExtractionAudit);
  assert.equal(ocr.metadata.ocrExtractionAudit.rows,2);
  assert.ok(analysis.batch15Counts.ocr>=1);
}));
