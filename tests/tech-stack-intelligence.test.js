const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const fssync=require('node:fs');
const os=require('node:os');
const path=require('node:path');

const { parseManifest,scanBannerText,analyzeWorkspaceTechStack }=require('../src/core/tech_stack_intelligence');
const { normalizeCveEntry,INDEX_SCHEMA }=require('../src/core/poc_reference_index');
const { scanWorkspace }=require('../src/core/finals_analyzer_batch18');

test('manifest parsers recover resolved package versions, canonical PURL and known CPE candidates',()=>{
  const lock=parseManifest('npm-lock',JSON.stringify({
    lockfileVersion:3,
    packages:{
      '':{name:'demo',version:'1.0.0'},
      'node_modules/express':{version:'4.18.2'},
      'node_modules/@scope/pkg':{version:'2.3.4',dev:true}
    }
  }),'package-lock.json');
  assert.ok(lock.some((item)=>item.name==='express'&&item.version==='4.18.2'&&item.purl==='pkg:npm/express@4.18.2'));
  assert.ok(lock.some((item)=>item.name==='@scope/pkg'&&item.version==='2.3.4'&&item.purl==='pkg:npm/%40scope/pkg@2.3.4'));

  const pom=parseManifest('maven-pom',`<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>`,'pom.xml');
  const log4j=pom.find((item)=>item.name==='org.apache.logging.log4j:log4j-core');
  assert.equal(log4j.version,'2.14.1');
  assert.equal(log4j.purl,'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1');
  assert.match(log4j.cpe.uri,/cpe:2\.3:a:apache:log4j:2\.14\.1/);
});

test('expanded lockfile parsers cover Yarn, pnpm and Go module versions',()=>{
  const yarn=parseManifest('yarn-lock','express@^4.18.0:\n  version "4.18.2"\n','yarn.lock');
  assert.ok(yarn.some((item)=>item.name==='express'&&item.version==='4.18.2'));
  const pnpm=parseManifest('pnpm-lock','packages:\n  express@4.18.2:\n    resolution: {}\n','pnpm-lock.yaml');
  assert.ok(pnpm.some((item)=>item.name==='express'&&item.version==='4.18.2'));
  const go=parseManifest('go-mod','module demo\nrequire github.com/gin-gonic/gin v1.9.1\nrequire (\n  golang.org/x/net v0.17.0\n)\n','go.mod');
  assert.ok(go.some((item)=>item.name==='github.com/gin-gonic/gin'&&item.version==='1.9.1'));
  assert.ok(go.some((item)=>item.name==='golang.org/x/net'&&item.version==='0.17.0'));
});

test('banner scanner extracts exact service versions conservatively',()=>{
  const rows=scanBannerText('Server: Apache/2.4.49\nOpenSSH_8.2p1 Ubuntu\nOpenSSL 1.1.1k','headers.txt');
  assert.ok(rows.some((item)=>item.name==='apache http server'&&item.version==='2.4.49'));
  assert.ok(rows.some((item)=>item.name==='openssh'&&item.version==='8.2p1'));
  assert.ok(rows.some((item)=>item.name==='openssl'&&item.version==='1.1.1k'));
});

test('workspace tech stack reads manifests under strict size budgets',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-tech-stack-'));
  try {
    await fs.writeFile(path.join(root,'requirements.txt'),'flask==2.0.3\nrequests>=2.28\n');
    await fs.writeFile(path.join(root,'Dockerfile'),'FROM python:3.10.14-slim\n');
    const analysis={files:[
      {path:'requirements.txt',name:'requirements.txt',size:(await fs.stat(path.join(root,'requirements.txt'))).size,metadata:{}},
      {path:'Dockerfile',name:'Dockerfile',size:(await fs.stat(path.join(root,'Dockerfile'))).size,metadata:{}}
    ]};
    const stack=await analyzeWorkspaceTechStack(root,analysis);
    assert.ok(stack.components.some((item)=>item.name==='flask'&&item.version==='2.0.3'));
    assert.ok(stack.components.some((item)=>item.name==='requests'&&item.constraint==='>=2.28'));
    assert.ok(stack.components.some((item)=>item.ecosystem==='docker'&&item.name==='python'&&item.version==='3.10.14-slim'));
    assert.ok(stack.purls.includes('pkg:pypi/flask@2.0.3'));
  } finally { await fs.rm(root,{recursive:true,force:true}); }
});

test('Batch18 reranks PoC metadata with component and exact version evidence',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-version-poc-'));
  try {
    await fs.writeFile(path.join(root,'pom.xml'),`<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>`);
    await fs.writeFile(path.join(root,'README.txt'),'Java logging service challenge. Inspect logging input and JNDI behavior.');
    const entry=normalizeCveEntry('CVE-2021-44228',[{
      name:'log4shell',full_name:'example/log4shell',html_url:'https://github.com/example/log4shell',
      description:'Apache Log4j 2.14.1 remote code execution through JNDI lookup',stargazers_count:100,topics:['log4j','rce','jndi']
    }]);
    const index={schema:INDEX_SCHEMA,generatedAt:new Date().toISOString(),stats:{cves:1,references:1},entries:[entry]};
    const analysis=await scanWorkspace(root,{pocIndex:index});
    assert.ok(analysis.version>=18);
    assert.ok(analysis.techStack.components.some((item)=>item.name==='org.apache.logging.log4j:log4j-core'&&item.version==='2.14.1'));
    const hit=analysis.pocReferences.matches.find((item)=>item.cve==='CVE-2021-44228');
    assert.ok(hit);
    assert.equal(hit.versionEvidence.state,'reference-version-match');
    assert.ok(hit.versionEvidence.matchedVersions.includes('2.14.1'));
    assert.ok(analysis.autopilot.automaticChecks.some((item)=>item.id==='tech-stack'));
    assert.ok(analysis.autopilot.actions.some((item)=>item.id==='version-correlated-poc'));
    assert.equal(analysis.batch18Counts.versionCorrelatedPocs,1);
  } finally { await fs.rm(root,{recursive:true,force:true}); }
});

test('renderer and compatibility entrypoint include tech stack intelligence',()=>{
  const root=path.join(__dirname,'..');
  const renderer=fssync.readFileSync(path.join(root,'renderer/workspace_autopilot.js'),'utf8');
  assert.doesNotThrow(()=>new Function(renderer));
  assert.match(renderer,/技术栈 \/ 依赖 \/ 版本/);
  const entry=fssync.readFileSync(path.join(root,'src/core/finals_analyzer_batch15.js'),'utf8');
  const match=entry.match(/finals_analyzer_batch(\d+)/);
  assert.ok(match&&Number(match[1])>=18,`compatibility wrapper must target Batch18 or newer, got ${match?.[1]||'none'}`);
});
