const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const fssync=require('node:fs');
const os=require('node:os');
const path=require('node:path');

const {INDEX_SCHEMA,normalizeAdvisory}=require('../src/core/offline_advisory_index');
const {scanWorkspace}=require('../src/core/finals_analyzer_batch21');

function advisory(){
  return normalizeAdvisory({
    id:'GHSA-demo-express',aliases:['CVE-2026-12345'],summary:'Express demo advisory',
    severity:[{type:'CVSS_V3',score:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'}],
    affected:[{package:{ecosystem:'npm',name:'express'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'4.0.0'},{fixed:'4.18.0'}]}]}]
  });
}
function index(){const item=advisory();return {schema:INDEX_SCHEMA,generatedAt:new Date().toISOString(),stats:{jsonFiles:1,advisories:1,packages:1,parseErrors:0},advisories:[item]};}
async function withWorkspace(fn){const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b21-'));try{return await fn(root);}finally{await fs.rm(root,{recursive:true,force:true});}}

test('Batch21 promotes affected component when source usage and external surface are co-located',()=>withWorkspace(async(root)=>{
  await fs.writeFile(path.join(root,'package.json'),JSON.stringify({dependencies:{express:'4.17.1'}}));
  await fs.writeFile(path.join(root,'server.js'),"const express=require('express'); const app=express(); app.get('/hello',(req,res)=>res.send('ok')); app.listen(3000);");
  const analysis=await scanWorkspace(root,{advisoryIndex:index()});
  assert.ok(analysis.version>=21);
  const card=analysis.vulnerabilityCandidates.candidates[0];
  assert.equal(card.applicability.state,'affected');
  assert.equal(card.reachability.state,'surface-co-located');
  assert.ok(card.reachability.usageFiles.includes('server.js'));
  assert.equal(card.priority.band,'hot');
  assert.ok(analysis.autopilot.automaticChecks.some((x)=>x.id==='component-reachability'));
}));

test('Batch21 keeps version-only affected dependencies in REVIEW',()=>withWorkspace(async(root)=>{
  await fs.writeFile(path.join(root,'package.json'),JSON.stringify({dependencies:{express:'4.17.1'}}));
  await fs.writeFile(path.join(root,'README.md'),'dependency fixture only');
  const analysis=await scanWorkspace(root,{advisoryIndex:index()});
  const card=analysis.vulnerabilityCandidates.candidates[0];
  assert.equal(card.applicability.state,'affected');
  assert.equal(card.reachability.state,'dependency-only');
  assert.equal(card.priority.band,'review');
  assert.equal(analysis.vulnerabilityCandidates.summary.dependencyOnly,1);
}));

test('tool workbench scrolls long prompt input/output independently and homepage uses only NewCyber title',()=>{
  const root=path.join(__dirname,'..');
  const css=fssync.readFileSync(path.join(root,'renderer/styles/layout_fix.css'),'utf8');
  const ui=fssync.readFileSync(path.join(root,'renderer/tool_ui.js'),'utf8');
  const html=fssync.readFileSync(path.join(root,'renderer/toolbox.html'),'utf8');
  const entry=fssync.readFileSync(path.join(root,'src/core/finals_analyzer_batch15.js'),'utf8');
  assert.match(css,/\.result-panel #tool-result\{flex:1;min-height:0;overflow:auto/);
  assert.match(css,/\.input-panel \.field\.grow textarea\{height:100%;min-height:160px;resize:vertical;overflow:auto/);
  assert.match(ui,/tool-home-head tool-home-head-minimal"><h1>NewCyber<\/h1>/);
  assert.doesNotMatch(ui,/LOCAL SECURITY WORKBENCH/);
  assert.match(html,/styles\/layout_fix\.css/);
  assert.match(entry,/finals_analyzer_batch21/);
});
