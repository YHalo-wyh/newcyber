const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const fssync=require('node:fs');
const os=require('node:os');
const path=require('node:path');

const {
  INDEX_SCHEMA,compareVersion,normalizeAdvisory,buildAdvisoryIndexFromDirectory,evaluateAffected
}=require('../src/core/offline_advisory_index');
const {scanWorkspace}=require('../src/core/finals_analyzer_batch19');

function log4jAdvisory() {
  return normalizeAdvisory({
    id:'GHSA-demo-log4j',aliases:['CVE-2021-44228'],summary:'Log4j JNDI lookup remote code execution',
    affected:[{
      package:{ecosystem:'Maven',name:'org.apache.logging.log4j:log4j-core'},
      ranges:[{type:'ECOSYSTEM',events:[{introduced:'2.0.0'},{fixed:'2.15.0'}]}]
    }]
  });
}

function indexFor(advisory) {
  return {schema:INDEX_SCHEMA,generatedAt:new Date().toISOString(),stats:{jsonFiles:1,advisories:1,packages:1,parseErrors:0},advisories:[advisory]};
}

async function writePom(root,version) {
  await fs.writeFile(path.join(root,'pom.xml'),`<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${version}</version></dependency></dependencies></project>`);
  await fs.writeFile(path.join(root,'README.txt'),'Logging challenge with JNDI lookup behavior.');
}

test('generic version comparator handles common CTF semantic versions and prereleases',()=>{
  assert.equal(compareVersion('2.14.1','2.15.0'),-1);
  assert.equal(compareVersion('2.15.0','2.15.0'),0);
  assert.equal(compareVersion('2.16.0','2.15.0'),1);
  assert.equal(compareVersion('1.0.0-rc.1','1.0.0'),-1);
  assert.equal(compareVersion('not-a-version','1.0.0'),null);
});

test('affected range evaluator distinguishes affected, fixed-side and unknown versions',()=>{
  const affected=log4jAdvisory().affected[0];
  assert.equal(evaluateAffected('2.14.1',affected).state,'affected');
  const fixed=evaluateAffected('2.17.1',affected);
  assert.equal(fixed.state,'not-affected');
  assert.ok(fixed.fixedVersions.includes('2.15.0'));
  assert.equal(evaluateAffected('vendor-build-x',affected).state,'unknown');
});

test('offline importer recursively builds compact OSV-compatible advisory index',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-osv-index-'));
  try {
    await fs.mkdir(path.join(root,'Maven'),{recursive:true});
    await fs.writeFile(path.join(root,'Maven','GHSA-demo.json'),JSON.stringify({
      id:'GHSA-demo',aliases:['CVE-2021-44228'],summary:'demo',
      affected:[{package:{ecosystem:'Maven',name:'org.apache.logging.log4j:log4j-core'},versions:['2.14.1']}]
    }));
    const index=await buildAdvisoryIndexFromDirectory(root);
    assert.equal(index.schema,INDEX_SCHEMA);
    assert.equal(index.stats.advisories,1);
    assert.equal(index.stats.packages,1);
    assert.equal(index.advisories[0].cves[0],'CVE-2021-44228');
  } finally { await fs.rm(root,{recursive:true,force:true}); }
});

test('Batch19 marks vulnerable exact version affected and promotes it in Autopilot',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b19-affected-'));
  try {
    await writePom(root,'2.14.1');
    const analysis=await scanWorkspace(root,{advisoryIndex:indexFor(log4jAdvisory())});
    assert.ok(analysis.version>=19);
    assert.equal(analysis.batch19Counts.affected,1);
    const hit=analysis.advisories.matches.find((x)=>x.cves.includes('CVE-2021-44228'));
    assert.ok(hit);
    assert.equal(hit.applicability.state,'affected');
    assert.equal(hit.component.version,'2.14.1');
    assert.ok(analysis.autopilot.automaticChecks.some((x)=>x.id==='offline-advisory'));
    assert.ok(analysis.autopilot.actions.some((x)=>x.id==='offline-advisory-affected'));
  } finally { await fs.rm(root,{recursive:true,force:true}); }
});

test('Batch19 does not call a post-fix version affected',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-b19-fixed-'));
  try {
    await writePom(root,'2.17.1');
    const analysis=await scanWorkspace(root,{advisoryIndex:indexFor(log4jAdvisory())});
    assert.equal(analysis.batch19Counts.affected,0);
    assert.equal(analysis.batch19Counts.notAffected,1);
    const hit=analysis.advisories.matches[0];
    assert.equal(hit.applicability.state,'not-affected');
    assert.equal(analysis.autopilot.actions.some((x)=>x.id==='offline-advisory-affected'),false);
  } finally { await fs.rm(root,{recursive:true,force:true}); }
});

test('compatibility entrypoint targets current analyzer',()=>{
  const entry=fssync.readFileSync(path.join(__dirname,'..','src/core/finals_analyzer_batch15.js'),'utf8');
  assert.match(entry,/finals_analyzer_batch22/);
});

test('Electron bridge persists advisory index and workspace renderer exposes one-click import',()=>{
  const root=path.join(__dirname,'..');
  const main=fssync.readFileSync(path.join(root,'main.js'),'utf8');
  const preload=fssync.readFileSync(path.join(root,'preload.js'),'utf8');
  const renderer=fssync.readFileSync(path.join(root,'renderer/workspace_autopilot.js'),'utf8');
  assert.doesNotThrow(()=>new Function(renderer));
  assert.match(main,/advisory:index-import/);
  assert.match(main,/advisoryIndexCache/);
  assert.match(main,/advisoryIndex:advisoryIndexCache/);
  assert.match(preload,/importAdvisoryIndex/);
  assert.match(renderer,/离线 Advisory 版本适用性/);
  assert.match(renderer,/data-advisory-index-import/);
});
