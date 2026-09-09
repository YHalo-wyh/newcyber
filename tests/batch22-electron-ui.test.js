const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const fssync=require('node:fs');
const os=require('node:os');
const path=require('node:path');

const {INDEX_SCHEMA,normalizeAdvisory}=require('../src/core/offline_advisory_index');
const {scanWorkspace}=require('../src/core/finals_analyzer_batch22');

function advisory(){
  return normalizeAdvisory({
    id:'GHSA-demo-lodash',aliases:['CVE-2026-22001'],summary:'Lodash merge demo advisory',
    severity:[{type:'CVSS_V3',score:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}],
    database_specific:{cwe_ids:['CWE-1321']},
    affected:[{package:{ecosystem:'npm',name:'lodash'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'4.0.0'},{fixed:'4.17.21'}]}]}]
  });
}
function index(){const item=advisory();return {schema:INDEX_SCHEMA,generatedAt:new Date().toISOString(),stats:{jsonFiles:1,advisories:1,packages:1,parseErrors:0},advisories:[item]};}
async function withWorkspace(fn){const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b22-'));try{return await fn(root);}finally{await fs.rm(root,{recursive:true,force:true});}}
async function writePackage(root){await fs.writeFile(path.join(root,'package.json'),JSON.stringify({dependencies:{lodash:'4.17.19',express:'4.17.1'}}));}

test('Batch22 promotes affected candidate only when external input flows into component API',()=>withWorkspace(async(root)=>{
  await writePackage(root);
  await fs.writeFile(path.join(root,'server.js'),[
    "const express=require('express');",
    "const lodash=require('lodash');",
    'const app=express();',
    "app.post('/merge',(req,res)=>{",
    '  const payload=req.body;',
    '  const forwarded=payload;',
    '  const result=lodash.merge({},forwarded);',
    '  res.json(result);',
    '});',
    'app.listen(3000);'
  ].join('\n'));
  const analysis=await scanWorkspace(root,{advisoryIndex:index()});
  assert.ok(analysis.version>=22);
  assert.equal(analysis.vulnerableApiFlow.summary.entryToApi,1);
  const card=analysis.vulnerabilityCandidates.candidates[0];
  assert.equal(card.applicability.state,'affected');
  assert.equal(card.dataflow.state,'entry-to-api');
  assert.equal(card.dataflow.flows[0].kind,'one-hop');
  assert.equal(card.dataflow.flows[0].api,'merge');
  assert.equal(card.priority.band,'hot');
  assert.ok(card.priority.dataflowAdjustment>0);
  assert.ok(analysis.autopilot.automaticChecks.some((x)=>x.id==='entry-to-vulnerable-api'));
  assert.ok(analysis.autopilot.actions.some((x)=>x.id==='vulnerable-api-flow'));
}));

test('Batch22 keeps a route-near component call in REVIEW when no request value reaches its arguments',()=>withWorkspace(async(root)=>{
  await writePackage(root);
  await fs.writeFile(path.join(root,'server.js'),[
    "const express=require('express');",
    "const lodash=require('lodash');",
    'const app=express();',
    'const defaults={role:"guest"};',
    "app.post('/merge',(req,res)=>{",
    '  const result=lodash.merge({},defaults);',
    '  res.json(result);',
    '});'
  ].join('\n'));
  const analysis=await scanWorkspace(root,{advisoryIndex:index()});
  const card=analysis.vulnerabilityCandidates.candidates[0];
  assert.equal(card.dataflow.state,'surface-to-api-nearby');
  assert.equal(card.priority.band,'review');
  assert.equal(analysis.vulnerabilityCandidates.summary.withAttackPath,0);
  assert.equal(analysis.vulnerabilityCandidates.summary.surfaceNearby,1);
}));

test('Electron shell uses native material, taskbar progress and always-on-top controls',()=>{
  const root=path.join(__dirname,'..');
  const pkg=JSON.parse(fssync.readFileSync(path.join(root,'package.json'),'utf8'));
  const shell=fssync.readFileSync(path.join(root,'electron_main.js'),'utf8');
  const preload=fssync.readFileSync(path.join(root,'preload.js'),'utf8');
  const chrome=fssync.readFileSync(path.join(root,'renderer/electron_chrome.js'),'utf8');
  const css=fssync.readFileSync(path.join(root,'renderer/styles/electron_chrome.css'),'utf8');
  const html=fssync.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  const candidates=fssync.readFileSync(path.join(root,'renderer/vulnerability_candidates.js'),'utf8');
  const entry=fssync.readFileSync(path.join(root,'src/core/finals_analyzer_batch15.js'),'utf8');
  assert.equal(pkg.main,'electron_main.js');
  assert.match(shell,/setBackgroundMaterial\('mica'\)/);
  assert.match(shell,/setVibrancy\('under-window'\)/);
  assert.match(shell,/setProgressBar\(2\)/);
  assert.match(shell,/setAlwaysOnTop/);
  assert.match(preload,/toggleAlwaysOnTop/);
  assert.match(preload,/setTaskProgress/);
  assert.doesNotThrow(()=>new Function(chrome));
  assert.doesNotThrow(()=>new Function(candidates));
  assert.match(chrome,/electron-native-cluster/);
  assert.match(css,/backdrop-filter:blur\(30px\)/);
  assert.match(html,/styles\/electron_chrome\.css/);
  assert.match(html,/electron_chrome\.js/);
  assert.match(candidates,/ENTRY → API/);
  assert.match(entry,/finals_analyzer_batch22/);
});
