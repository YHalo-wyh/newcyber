const fsp = require('fs/promises');
const path = require('path');

const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_MANIFESTS = 96;
const MAX_COMPONENTS = 1600;
const MAX_BANNER_FILES = 32;
const MAX_BANNER_BYTES = 256 * 1024;

const KNOWN_CPE = Object.freeze([
  { ecosystem:'maven', names:['org.apache.logging.log4j:log4j-core','org.apache.logging.log4j:log4j-api'], vendor:'apache', product:'log4j' },
  { ecosystem:'maven', names:['org.apache.struts:struts2-core'], vendor:'apache', product:'struts' },
  { ecosystem:'generic', names:['apache http server','apache','httpd'], vendor:'apache', product:'http_server' },
  { ecosystem:'generic', names:['apache tomcat','tomcat'], vendor:'apache', product:'tomcat' },
  { ecosystem:'generic', names:['openssl'], vendor:'openssl', product:'openssl' },
  { ecosystem:'generic', names:['openssh'], vendor:'openbsd', product:'openssh' }
]);

const BANNERS = Object.freeze([
  { name:'apache http server', ecosystem:'generic', regex:/\bApache(?:\/|\s+)(\d+\.\d+(?:\.\d+){0,2})\b/gi },
  { name:'apache tomcat', ecosystem:'generic', regex:/\b(?:Apache\s+)?Tomcat(?:\/|\s+)(\d+\.\d+(?:\.\d+){0,2})\b/gi },
  { name:'nginx', ecosystem:'generic', regex:/\bnginx(?:\/|\s+)(\d+\.\d+(?:\.\d+){0,2})\b/gi },
  { name:'openssl', ecosystem:'generic', regex:/\bOpenSSL\s+(\d+\.\d+(?:\.\d+){0,2}[a-z]?)\b/gi },
  { name:'openssh', ecosystem:'generic', regex:/\bOpenSSH[_\s-](\d+\.\d+(?:p\d+)?)\b/gi },
  { name:'php', ecosystem:'generic', regex:/\bPHP(?:\/|\s+)(\d+\.\d+(?:\.\d+){0,2})\b/gi },
  { name:'python', ecosystem:'generic', regex:/\bPython(?:\/|\s+)(\d+\.\d+(?:\.\d+){0,2})\b/gi },
  { name:'node.js', ecosystem:'generic', regex:/\bNode(?:\.js)?(?:\/|\s+|\bv)(\d+\.\d+(?:\.\d+){0,2})\b/gi },
  { name:'spring boot', ecosystem:'maven', regex:/\bSpring\s+Boot(?:\/|\s+)(\d+\.\d+(?:\.\d+){0,2})\b/gi },
  { name:'log4j', ecosystem:'maven', regex:/\bLog4j(?:\/|\s+)(\d+\.\d+(?:\.\d+){0,2})\b/gi }
]);

function cleanName(value='') {
  return String(value).trim().replace(/^['"]|['"]$/g,'').slice(0,240);
}

function cleanVersion(value='') {
  return String(value).trim().replace(/^['"]|['"]$/g,'').slice(0,120);
}

function exactVersionFromConstraint(raw='') {
  const value=cleanVersion(raw);
  if (!value) return null;
  const match=value.match(/^(?:===?|v)?(\d+(?:\.\d+){1,3}(?:[-+._]?[0-9A-Za-z.-]+)?)$/);
  return match?match[1]:null;
}

function purlEncode(value='') {
  return encodeURIComponent(String(value)).replace(/%2F/gi,'/');
}

function purl(component) {
  if (!component?.name || !component?.version) return null;
  const version=encodeURIComponent(component.version);
  if (component.ecosystem==='maven') {
    const [group,artifact]=component.name.split(':');
    if (!group || !artifact) return null;
    return `pkg:maven/${purlEncode(group)}/${purlEncode(artifact)}@${version}`;
  }
  if (component.ecosystem==='npm') {
    const name=component.name.startsWith('@')?`%40${purlEncode(component.name.slice(1))}`:purlEncode(component.name);
    return `pkg:npm/${name}@${version}`;
  }
  const type=({pypi:'pypi',golang:'golang',cargo:'cargo',composer:'composer',gem:'gem',docker:'docker'})[component.ecosystem];
  return type?`pkg:${type}/${purlEncode(component.name)}@${version}`:null;
}

function cpeCandidate(component) {
  if (!component?.name || !component?.version) return null;
  const name=component.name.toLowerCase();
  const hit=KNOWN_CPE.find((item)=>item.names.includes(name)&&(item.ecosystem===component.ecosystem||item.ecosystem==='generic'));
  if (!hit) return null;
  const version=component.version.replace(/[^0-9A-Za-z._-]/g,'');
  if (!version) return null;
  return {uri:`cpe:2.3:a:${hit.vendor}:${hit.product}:${version}:*:*:*:*:*:*:*`,confidence:'known-map',vendor:hit.vendor,product:hit.product};
}

function component({ecosystem,name,version=null,constraint=null,scope=null,source,evidence=null,direct=false,resolved=false}) {
  name=cleanName(name).toLowerCase();
  version=version?cleanVersion(version).replace(/^v(?=\d)/i,''):null;
  constraint=constraint?cleanVersion(constraint):null;
  if (!name) return null;
  const out={ecosystem,name,version,constraint,scope,source,evidence:evidence||null,direct:Boolean(direct),resolved:Boolean(resolved||version)};
  out.purl=purl(out);
  out.cpe=cpeCandidate(out);
  return out;
}

function manifestKind(filePath='') {
  const base=path.basename(String(filePath)).toLowerCase();
  if (base==='package.json') return 'npm-package';
  if (base==='package-lock.json'||base==='npm-shrinkwrap.json') return 'npm-lock';
  if (base==='yarn.lock') return 'yarn-lock';
  if (base==='pnpm-lock.yaml'||base==='pnpm-lock.yml') return 'pnpm-lock';
  if (base==='requirements.txt'||/^requirements[-_.].*\.txt$/.test(base)) return 'pip-requirements';
  if (base==='pipfile.lock') return 'pipfile-lock';
  if (base==='poetry.lock'||base==='uv.lock') return 'poetry-lock';
  if (base==='pyproject.toml') return 'pyproject';
  if (base==='pom.xml') return 'maven-pom';
  if (base==='build.gradle'||base==='build.gradle.kts'||base==='gradle.lockfile') return 'gradle';
  if (base==='go.mod') return 'go-mod';
  if (base==='go.sum') return 'go-sum';
  if (base==='cargo.lock') return 'cargo-lock';
  if (base==='cargo.toml') return 'cargo-toml';
  if (base==='composer.json') return 'composer-json';
  if (base==='composer.lock') return 'composer-lock';
  if (base==='gemfile.lock') return 'gem-lock';
  if (base==='dockerfile'||base.startsWith('dockerfile.')) return 'dockerfile';
  if (/^(?:docker-)?compose(?:\.[^.]+)?\.(?:ya?ml)$/i.test(base)||/^docker-compose\.ya?ml$/i.test(base)) return 'compose';
  return null;
}

function parseJson(text) { try{return JSON.parse(text);}catch{return null;} }

function pushMapComponents(out,source,ecosystem,values,scope,direct=true) {
  if (!values||typeof values!=='object') return;
  for (const [name,raw] of Object.entries(values)) {
    if (raw==null||typeof raw==='object') continue;
    const exact=exactVersionFromConstraint(raw);
    out.push(component({ecosystem,name,version:exact,constraint:String(raw),scope,source,direct,resolved:Boolean(exact)}));
  }
}

function parsePackageJson(text,source) {
  const json=parseJson(text); if (!json) return [];
  const out=[];
  pushMapComponents(out,source,'npm',json.dependencies,'runtime');
  pushMapComponents(out,source,'npm',json.devDependencies,'dev');
  pushMapComponents(out,source,'npm',json.optionalDependencies,'optional');
  pushMapComponents(out,source,'npm',json.peerDependencies,'peer');
  for (const [runtime,value] of Object.entries(json.engines||{})) {
    const exact=exactVersionFromConstraint(value);
    out.push(component({ecosystem:'runtime',name:runtime,version:exact,constraint:String(value),scope:'engine',source,direct:true,resolved:Boolean(exact)}));
  }
  return out.filter(Boolean);
}

function packageNameFromLockPath(value='') {
  const normalized=String(value).replace(/\\/g,'/');
  const pos=normalized.lastIndexOf('node_modules/');
  return pos>=0?normalized.slice(pos+'node_modules/'.length):null;
}

function parsePackageLock(text,source) {
  const json=parseJson(text); if (!json) return [];
  const out=[];
  if (json.packages&&typeof json.packages==='object') {
    for (const [pkgPath,meta] of Object.entries(json.packages)) {
      if (!pkgPath||!meta?.version) continue;
      const name=meta.name||packageNameFromLockPath(pkgPath); if (!name) continue;
      const nested=pkgPath.replace(/\\/g,'/').split('/node_modules/').length>2;
      out.push(component({ecosystem:'npm',name,version:String(meta.version),scope:meta.dev?'dev':'resolved',source,evidence:pkgPath,direct:!nested,resolved:true}));
    }
  } else if (json.dependencies&&typeof json.dependencies==='object') {
    for (const [name,meta] of Object.entries(json.dependencies)) if (meta?.version) out.push(component({ecosystem:'npm',name,version:String(meta.version),scope:meta.dev?'dev':'resolved',source,direct:true,resolved:true}));
  }
  return out.filter(Boolean);
}

function yarnSelectorName(selector='') {
  let value=selector.trim().replace(/^['"]|['"]$/g,'');
  if (value.startsWith('@')) {
    const slash=value.indexOf('/');
    const at=value.indexOf('@',slash+1);
    return at>0?value.slice(0,at):value;
  }
  const at=value.indexOf('@');
  return at>0?value.slice(0,at):value;
}

function parseYarnLock(text,source) {
  const out=[];
  const lines=text.split(/\r?\n/);
  let selectors=[];
  for (let i=0;i<lines.length;i+=1) {
    if (/^\S.*:\s*$/.test(lines[i])&&!/^__metadata:/.test(lines[i])) selectors=lines[i].slice(0,-1).split(',').map((x)=>x.trim());
    const m=lines[i].match(/^\s+version\s+["']?([^"'\s]+)["']?/);
    if (!m||!selectors.length) continue;
    const names=[...new Set(selectors.map(yarnSelectorName).filter(Boolean))];
    for (const name of names) out.push(component({ecosystem:'npm',name,version:m[1],scope:'resolved',source,direct:false,resolved:true}));
  }
  return out.filter(Boolean);
}

function parsePnpmLock(text,source) {
  const out=[];
  for (const m of text.matchAll(/^\s{2,8}["']?((?:@[^/:\s]+\/)?[^@:\s"']+)@(\d+\.\d+(?:\.\d+){0,2}[^:\s"']*)["']?:\s*$/gm)) {
    out.push(component({ecosystem:'npm',name:m[1],version:m[2],scope:'resolved',source,direct:false,resolved:true}));
  }
  return out.filter(Boolean);
}

function parseRequirements(text,source) {
  const out=[];
  for (const rawLine of text.split(/\r?\n/)) {
    const line=rawLine.replace(/\s+#.*$/,'').trim();
    if (!line||/^[-#]/.test(line)) continue;
    const m=line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*((?:===|==|~=|>=|<=|!=|>|<).+)?$/);
    if (!m) continue;
    const constraint=cleanVersion(m[2]||'');
    const exact=exactVersionFromConstraint(constraint);
    out.push(component({ecosystem:'pypi',name:m[1],version:exact,constraint:constraint||null,scope:'runtime',source,direct:true,resolved:Boolean(exact),evidence:line.slice(0,180)}));
  }
  return out.filter(Boolean);
}

function parsePipfileLock(text,source) {
  const json=parseJson(text); if (!json) return [];
  const out=[];
  for (const [scope,values] of [['runtime',json.default],['dev',json.develop]]) {
    for (const [name,meta] of Object.entries(values||{})) {
      const raw=typeof meta==='string'?meta:meta?.version;
      const exact=exactVersionFromConstraint(raw||'');
      out.push(component({ecosystem:'pypi',name,version:exact,constraint:raw||null,scope,source,direct:true,resolved:Boolean(exact)}));
    }
  }
  return out.filter(Boolean);
}

function parsePoetryLock(text,source) {
  const out=[];
  for (const block of text.split(/\[\[package\]\]/).slice(1)) {
    const name=block.match(/^\s*name\s*=\s*["']([^"']+)/m)?.[1];
    const version=block.match(/^\s*version\s*=\s*["']([^"']+)/m)?.[1];
    if (name&&version) out.push(component({ecosystem:'pypi',name,version,scope:'resolved',source,resolved:true}));
  }
  return out.filter(Boolean);
}

function parsePyproject(text,source) {
  const out=[]; let poetry=false;
  for (const raw of text.split(/\r?\n/)) {
    const line=raw.trim();
    if (/^\[tool\.poetry\.dependencies\]$/i.test(line)){poetry=true;continue;}
    if (/^\[/.test(line)){poetry=false;continue;}
    if (poetry) {
      const m=line.match(/^([A-Za-z0-9_.-]+)\s*=\s*["']([^"']+)["']/);
      if (m&&m[1].toLowerCase()!=='python') {
        const exact=exactVersionFromConstraint(m[2]);
        out.push(component({ecosystem:'pypi',name:m[1],version:exact,constraint:m[2],scope:'runtime',source,direct:true,resolved:Boolean(exact)}));
      }
    }
  }
  for (const m of text.matchAll(/["']([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*((?:===|==|~=|>=|<=|!=|>|<)[^"']+)["']/g)) {
    const exact=exactVersionFromConstraint(m[2]);
    out.push(component({ecosystem:'pypi',name:m[1],version:exact,constraint:m[2],scope:'project-dependency',source,direct:true,resolved:Boolean(exact)}));
  }
  return out.filter(Boolean);
}

function parsePom(text,source) {
  const out=[]; const properties={};
  for (const m of text.matchAll(/<([A-Za-z0-9_.-]+)>\s*([^<>]{1,120})\s*<\/\1>/g)) if (/\.version$/i.test(m[1])) properties[m[1]]=m[2].trim();
  for (const m of text.matchAll(/<dependency>\s*([\s\S]*?)<\/dependency>/gi)) {
    const block=m[1];
    const group=block.match(/<groupId>\s*([^<]+)<\/groupId>/i)?.[1]?.trim();
    const artifact=block.match(/<artifactId>\s*([^<]+)<\/artifactId>/i)?.[1]?.trim();
    let version=block.match(/<version>\s*([^<]+)<\/version>/i)?.[1]?.trim()||null;
    const scope=block.match(/<scope>\s*([^<]+)<\/scope>/i)?.[1]?.trim()||'runtime';
    if (version&&/^\$\{[^}]+\}$/.test(version)) version=properties[version.slice(2,-1)]||version;
    if (group&&artifact) out.push(component({ecosystem:'maven',name:`${group}:${artifact}`,version:exactVersionFromConstraint(version)||version,constraint:version,scope,source,direct:true,resolved:Boolean(version&&!/^\$\{/.test(version))}));
  }
  return out.filter(Boolean);
}

function parseGradle(text,source) {
  const out=[];
  for (const m of text.matchAll(/\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|compile)\s*\(?\s*["']([^:"']+):([^:"']+):([^"']+)["']/g)) out.push(component({ecosystem:'maven',name:`${m[1]}:${m[2]}`,version:exactVersionFromConstraint(m[3])||m[3],constraint:m[3],scope:'gradle',source,direct:true,resolved:true}));
  for (const m of text.matchAll(/^\s*([^:#\s]+):([^:#\s]+):(\d+\.\d+[^=\s]*)=/gm)) out.push(component({ecosystem:'maven',name:`${m[1]}:${m[2]}`,version:m[3],scope:'gradle-lock',source,resolved:true}));
  return out.filter(Boolean);
}

function parseGoMod(text,source) {
  const out=[];
  for (const m of text.matchAll(/^\s*require\s+([^\s]+)\s+(v\d+\.\d+(?:\.\d+)?[^\s]*)/gm)) out.push(component({ecosystem:'golang',name:m[1],version:m[2].replace(/^v/,''),scope:'require',source,direct:true,resolved:true}));
  const block=text.match(/\brequire\s*\(([\s\S]*?)\)/m)?.[1]||'';
  for (const m of block.matchAll(/^\s*([^\s/][^\s]*)\s+(v\d+\.\d+(?:\.\d+)?[^\s]*)/gm)) out.push(component({ecosystem:'golang',name:m[1],version:m[2].replace(/^v/,''),scope:'require',source,direct:true,resolved:true}));
  return out.filter(Boolean);
}

function parseGoSum(text,source) {
  const out=[];
  for (const m of text.matchAll(/^([^\s]+)\s+v(\d+\.\d+(?:\.\d+)?[^\s/]*)\s+h1:/gm)) out.push(component({ecosystem:'golang',name:m[1],version:m[2],scope:'resolved',source,resolved:true}));
  return out.filter(Boolean);
}

function parseCargoLock(text,source) {
  const out=[];
  for (const block of text.split(/\[\[package\]\]/).slice(1)) {
    const name=block.match(/^\s*name\s*=\s*["']([^"']+)/m)?.[1];
    const version=block.match(/^\s*version\s*=\s*["']([^"']+)/m)?.[1];
    if (name&&version) out.push(component({ecosystem:'cargo',name,version,scope:'resolved',source,resolved:true}));
  }
  return out.filter(Boolean);
}

function parseCargoToml(text,source) {
  const out=[]; let deps=false;
  for (const raw of text.split(/\r?\n/)) {
    const line=raw.trim();
    if (/^\[(?:dev-|build-)?dependencies(?:\.[^\]]+)?\]$/i.test(line)){deps=true;continue;}
    if (/^\[/.test(line)){deps=false;continue;}
    if (!deps) continue;
    let m=line.match(/^([A-Za-z0-9_.-]+)\s*=\s*["']([^"']+)["']/);
    if (!m) m=line.match(/^([A-Za-z0-9_.-]+)\s*=\s*\{[^}]*\bversion\s*=\s*["']([^"']+)["']/);
    if (!m) continue;
    const exact=exactVersionFromConstraint(m[2]);
    out.push(component({ecosystem:'cargo',name:m[1],version:exact,constraint:m[2],scope:'dependency',source,direct:true,resolved:Boolean(exact)}));
  }
  return out.filter(Boolean);
}

function parseComposer(text,source,lock=false) {
  const json=parseJson(text); if (!json) return [];
  const out=[];
  if (lock) {
    for (const meta of [...(json.packages||[]),...(json['packages-dev']||[])]) if (meta?.name&&meta?.version) out.push(component({ecosystem:'composer',name:meta.name,version:String(meta.version).replace(/^v/,''),scope:'resolved',source,resolved:true}));
  } else {
    pushMapComponents(out,source,'composer',json.require,'runtime');
    pushMapComponents(out,source,'composer',json['require-dev'],'dev');
  }
  return out.filter(Boolean);
}

function parseGemLock(text,source) {
  const out=[];
  for (const m of text.matchAll(/^\s{4}([A-Za-z0-9_.-]+)\s+\((\d+\.\d+(?:\.\d+){0,2}[^)]*)\)/gm)) out.push(component({ecosystem:'gem',name:m[1],version:m[2],scope:'resolved',source,resolved:true}));
  return out.filter(Boolean);
}

function parseDockerfile(text,source) {
  const out=[];
  for (const m of text.matchAll(/^\s*FROM\s+(?:--platform=\S+\s+)?([^\s:@]+(?:\/[^\s:@]+)*)(?::([^\s@]+))?(?:@\S+)?/gmi)) {
    const tag=m[2]||null;
    out.push(component({ecosystem:'docker',name:m[1],version:tag&&tag!=='latest'?tag:null,constraint:tag,scope:'base-image',source,direct:true,resolved:Boolean(tag&&tag!=='latest'),evidence:m[0].trim()}));
  }
  return out.filter(Boolean);
}

function splitImage(value='') {
  const clean=String(value).trim().replace(/^['"]|['"]$/g,'').split('@')[0];
  const slash=clean.lastIndexOf('/');
  const colon=clean.lastIndexOf(':');
  if (colon>slash) return {name:clean.slice(0,colon),tag:clean.slice(colon+1)};
  return {name:clean,tag:null};
}

function parseCompose(text,source) {
  const out=[];
  for (const m of text.matchAll(/^\s*image:\s*([^\s#]+)\s*$/gmi)) {
    const image=splitImage(m[1]);
    out.push(component({ecosystem:'docker',name:image.name,version:image.tag&&image.tag!=='latest'?image.tag:null,constraint:image.tag,scope:'compose-image',source,direct:true,resolved:Boolean(image.tag&&image.tag!=='latest'),evidence:m[0].trim()}));
  }
  return out.filter(Boolean);
}

function parseManifest(kind,text,source) {
  const fn=({
    'npm-package':parsePackageJson,'npm-lock':parsePackageLock,'yarn-lock':parseYarnLock,'pnpm-lock':parsePnpmLock,
    'pip-requirements':parseRequirements,'pipfile-lock':parsePipfileLock,'poetry-lock':parsePoetryLock,pyproject:parsePyproject,
    'maven-pom':parsePom,gradle:parseGradle,'go-mod':parseGoMod,'go-sum':parseGoSum,'cargo-lock':parseCargoLock,'cargo-toml':parseCargoToml,
    'composer-json':(value,src)=>parseComposer(value,src,false),'composer-lock':(value,src)=>parseComposer(value,src,true),
    'gem-lock':parseGemLock,dockerfile:parseDockerfile,compose:parseCompose
  })[kind];
  return fn?fn(text,source):[];
}

function scanBannerText(text,source) {
  const out=[];
  for (const rule of BANNERS) {
    rule.regex.lastIndex=0;
    for (const match of text.matchAll(rule.regex)) {
      out.push(component({ecosystem:rule.ecosystem,name:rule.name,version:match[1],scope:'banner',source,direct:false,resolved:true,evidence:match[0].slice(0,180)}));
      if (out.length>=32) return out.filter(Boolean);
    }
  }
  return out.filter(Boolean);
}

function mergeComponents(items) {
  const map=new Map();
  for (const item of items.filter(Boolean)) {
    const key=`${item.ecosystem}:${item.name}:${item.version||item.constraint||''}`;
    const existing=map.get(key);
    if (!existing) map.set(key,{...item,sources:[item.source],evidenceList:item.evidence?[item.evidence]:[]});
    else {
      if (item.source&&!existing.sources.includes(item.source)) existing.sources.push(item.source);
      if (item.evidence&&!existing.evidenceList.includes(item.evidence)) existing.evidenceList.push(item.evidence);
      existing.direct||=item.direct;
      existing.resolved||=item.resolved;
      if (!existing.purl&&item.purl) existing.purl=item.purl;
      if (!existing.cpe&&item.cpe) existing.cpe=item.cpe;
    }
  }
  return [...map.values()].slice(0,MAX_COMPONENTS);
}

function queryTextFromTechStack(stack) {
  const chunks=[];
  for (const item of (stack?.components||[]).slice(0,600)) chunks.push(item.name,item.version||'',item.constraint||'',item.cpe?.product||'',item.cpe?.vendor||'');
  for (const runtime of stack?.runtimes||[]) chunks.push(runtime.name,runtime.version||'',runtime.constraint||'');
  return chunks.filter(Boolean).join(' ');
}

async function readBounded(filePath,sizeLimit) {
  const stat=await fsp.stat(filePath);
  if (!stat.isFile()||stat.size<=0||stat.size>sizeLimit) return null;
  return fsp.readFile(filePath,'utf8');
}

async function analyzeWorkspaceTechStack(rootPath,analysis) {
  const manifestFiles=(analysis.files||[]).filter((file)=>manifestKind(file.path)).slice(0,MAX_MANIFESTS);
  const components=[]; const manifests=[];
  for (const file of manifestFiles) {
    const kind=manifestKind(file.path);
    try {
      const text=await readBounded(path.join(rootPath,file.path),MAX_MANIFEST_BYTES);
      if (text==null) continue;
      const parsed=parseManifest(kind,text,file.path).filter(Boolean);
      components.push(...parsed);
      manifests.push({path:file.path,kind,components:parsed.length});
      file.metadata={...(file.metadata||{}),techStack:{kind,components:parsed.slice(0,120)}};
    } catch (error) { manifests.push({path:file.path,kind,components:0,error:error.message}); }
  }

  const bannerCandidates=(analysis.files||[])
    .filter((file)=>file.size>0&&file.size<=2*1024*1024&&/(?:log|txt|md|conf|cfg|ini|yaml|yml|json|xml|html|http|headers?|response|banner|readme|docker)/i.test(`${file.name} ${file.path}`))
    .slice(0,MAX_BANNER_FILES);
  let bannerFilesRead=0;
  for (const file of bannerCandidates) {
    try {
      const handle=await fsp.open(path.join(rootPath,file.path),'r');
      try {
        const size=Math.min(file.size,MAX_BANNER_BYTES); const buffer=Buffer.alloc(size);
        const {bytesRead}=await handle.read(buffer,0,size,0); const data=buffer.subarray(0,bytesRead);
        if (data.includes(0)) continue;
        components.push(...scanBannerText(data.toString('utf8'),file.path)); bannerFilesRead+=1;
      } finally { await handle.close(); }
    } catch {}
  }

  const merged=mergeComponents(components);
  const exact=merged.filter((item)=>item.version);
  const direct=merged.filter((item)=>item.direct);
  const cpes=merged.filter((item)=>item.cpe).map((item)=>({name:item.name,version:item.version,...item.cpe,source:item.sources?.[0]||item.source}));
  const purls=merged.filter((item)=>item.purl).map((item)=>item.purl);
  const ecosystems={}; for (const item of merged) ecosystems[item.ecosystem]=(ecosystems[item.ecosystem]||0)+1;
  const runtimes=merged.filter((item)=>item.ecosystem==='runtime'||item.scope==='base-image'||item.scope==='compose-image'||item.scope==='banner').slice(0,120);
  return {
    schema:'newcyber.tech-stack.v1',
    stats:{manifests:manifests.length,components:merged.length,exactVersions:exact.length,directDependencies:direct.length,cpeCandidates:cpes.length,bannerFilesRead},
    ecosystems,manifests,components:merged,runtimes,purls:[...new Set(purls)].slice(0,800),cpeCandidates:cpes.slice(0,160)
  };
}

module.exports={MAX_MANIFEST_BYTES,manifestKind,exactVersionFromConstraint,parseManifest,scanBannerText,mergeComponents,queryTextFromTechStack,analyzeWorkspaceTechStack};
