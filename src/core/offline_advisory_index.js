const fsp=require('fs/promises');
const path=require('path');
const {compareEcosystemVersion,evaluateGitBoundary}=require('./version_semantics');

const INDEX_SCHEMA='newcyber.offline-advisory-index.v1';
const DEFAULT_MAX_ADVISORIES=120000;
const DEFAULT_CONCURRENCY=24;
const MAX_SUMMARY=480;

const ECOSYSTEM_MAP=Object.freeze({
  npm:'npm',
  pypi:'pypi',
  maven:'maven',
  go:'golang',
  golang:'golang',
  'crates.io':'cargo',
  packagist:'composer',
  rubygems:'gem',
  docker:'docker'
});

function normalizeName(value='') {
  return String(value).trim().toLowerCase();
}

function normalizeEcosystem(value='') {
  const key=String(value||'').trim().toLowerCase();
  return ECOSYSTEM_MAP[key]||key;
}

function cveAliases(advisory={}) {
  return [...new Set([advisory.id,...(advisory.aliases||[])]
    .filter((x)=>/^CVE-\d{4}-\d{4,7}$/i.test(String(x||'')))
    .map((x)=>String(x).toUpperCase()))];
}

function cweAliases(advisory={}) {
  const db=advisory.database_specific||{};
  const values=[...(db.cwe_ids||[]),...(db.cwes||[]),...(advisory.cwes||[])];
  if (db.cwe_id) values.push(db.cwe_id);
  return [...new Set(values
    .map((x)=>String(x||'').toUpperCase())
    .filter((x)=>/^CWE-\d+$/.test(x)))].slice(0,32);
}

function compareVersion(a,b) {
  return compareEcosystemVersion(a,b,'generic','SEMVER');
}

function intervalContains(version,interval,ecosystem='') {
  if (String(interval?.type||'').toUpperCase()==='GIT') return null;
  const rangeType=String(interval?.type||'ECOSYSTEM').toUpperCase();
  const compare=(boundary)=>compareEcosystemVersion(version,boundary,ecosystem,rangeType);
  const lower=interval.introduced&&interval.introduced!=='0'?compare(interval.introduced):1;
  if (lower===null) return null;
  if (interval.introduced&&interval.introduced!=='0'&&lower<0) return false;
  if (interval.fixed) {
    const c=compare(interval.fixed); if (c===null) return null; return c<0;
  }
  if (interval.lastAffected) {
    const c=compare(interval.lastAffected); if (c===null) return null; return c<=0;
  }
  if (interval.limit) {
    const c=compare(interval.limit); if (c===null) return null; return c<0;
  }
  return true;
}

function rangesToIntervals(ranges=[]) {
  const out=[];
  for (const range of ranges||[]) {
    const type=String(range?.type||'').toUpperCase();
    if (!['SEMVER','ECOSYSTEM','GIT'].includes(type)) continue;
    let introduced='0';
    for (const event of range.events||[]) {
      if (event.introduced!==undefined) { introduced=String(event.introduced); continue; }
      if (event.fixed!==undefined) {
        out.push({type,introduced,fixed:String(event.fixed),repo:range.repo||null});
        introduced=null;
        continue;
      }
      if (event.last_affected!==undefined) {
        out.push({type,introduced,lastAffected:String(event.last_affected),repo:range.repo||null});
        introduced=null;
        continue;
      }
      if (event.limit!==undefined) {
        out.push({type,introduced,limit:String(event.limit),repo:range.repo||null});
        introduced=null;
      }
    }
    if (introduced!==null) out.push({type,introduced,repo:range.repo||null});
  }
  return out;
}

function normalizeAffected(affected={}) {
  const pkg=affected.package||{};
  const ecosystem=normalizeEcosystem(pkg.ecosystem);
  const name=normalizeName(pkg.name);
  if (!ecosystem||!name) return null;
  return {
    ecosystem,
    name,
    purl:pkg.purl||null,
    versions:[...new Set((affected.versions||[]).map(String))].slice(0,4096),
    intervals:rangesToIntervals(affected.ranges||[]).slice(0,256),
    databaseSpecific:affected.database_specific||null,
    ecosystemSpecific:affected.ecosystem_specific||null
  };
}

function normalizeAdvisory(raw={}) {
  if (!raw||typeof raw!=='object'||!raw.id) return null;
  const affected=(raw.affected||[]).map(normalizeAffected).filter(Boolean);
  if (!affected.length) return null;
  return {
    id:String(raw.id),
    aliases:[...new Set((raw.aliases||[]).map(String))].slice(0,40),
    cves:cveAliases(raw),
    cwes:cweAliases(raw),
    summary:String(raw.summary||raw.details||'').replace(/\s+/g,' ').trim().slice(0,MAX_SUMMARY)||null,
    published:raw.published||null,
    modified:raw.modified||null,
    withdrawn:raw.withdrawn||null,
    severity:Array.isArray(raw.severity)?raw.severity.slice(0,8).map((x)=>({type:x?.type||null,score:x?.score||null})):[],
    databaseSpecific:raw.database_specific||null,
    references:Array.isArray(raw.references)?raw.references.slice(0,20).map((x)=>({type:x?.type||null,url:x?.url||null})):[],
    affected
  };
}

async function mapLimit(items,limit,worker) {
  const out=new Array(items.length); let cursor=0;
  const runners=Array.from({length:Math.max(1,Math.min(limit,items.length||1))},async()=>{
    while (true) {
      const index=cursor++; if (index>=items.length) break;
      out[index]=await worker(items[index],index);
    }
  });
  await Promise.all(runners); return out;
}

async function collectJsonFiles(root,maxFiles) {
  const files=[]; const queue=[root];
  while (queue.length&&files.length<maxFiles) {
    const dir=queue.shift(); let entries=[];
    try { entries=await fsp.readdir(dir,{withFileTypes:true}); } catch { continue; }
    for (const entry of entries) {
      if (files.length>=maxFiles) break;
      const full=path.join(dir,entry.name);
      if (entry.isDirectory()) queue.push(full);
      else if (entry.isFile()&&/\.json$/i.test(entry.name)) files.push(full);
    }
  }
  return files;
}

async function buildAdvisoryIndexFromDirectory(rootPath,options={}) {
  const root=path.resolve(String(rootPath||''));
  const stat=await fsp.stat(root);
  if (!stat.isDirectory()) throw new Error('离线 advisory 数据源必须是目录');
  const maxAdvisories=Math.max(1,Math.min(Number(options.maxAdvisories)||DEFAULT_MAX_ADVISORIES,300000));
  const files=await collectJsonFiles(root,maxAdvisories);
  if (!files.length) throw new Error('目录中未找到 OSV-compatible JSON advisory');
  let parseErrors=0;
  const parsed=await mapLimit(files,Number(options.concurrency)||DEFAULT_CONCURRENCY,async(filePath)=>{
    try {
      const raw=JSON.parse(await fsp.readFile(filePath,'utf8'));
      if (Array.isArray(raw)) return raw.map(normalizeAdvisory).filter(Boolean);
      return [normalizeAdvisory(raw)].filter(Boolean);
    } catch { parseErrors+=1; return []; }
  });
  const advisories=parsed.flat().slice(0,maxAdvisories);
  const packages=new Set();
  for (const adv of advisories) for (const item of adv.affected) packages.add(`${item.ecosystem}:${item.name}`);
  return {
    schema:INDEX_SCHEMA,
    source:{kind:'OSV-compatible-offline-directory',importedFrom:root,note:'仅解析本地 advisory JSON；NewCyber 不联网查询、不下载 PoC、不执行验证请求。'},
    generatedAt:new Date().toISOString(),
    stats:{jsonFiles:files.length,advisories:advisories.length,packages:packages.size,parseErrors},
    advisories
  };
}

function validateIndex(index) {
  if (!index||index.schema!==INDEX_SCHEMA||!Array.isArray(index.advisories)) throw new Error('离线 advisory 索引格式不受支持');
  return index;
}

async function loadAdvisoryIndexFile(filePath) {
  return validateIndex(JSON.parse(await fsp.readFile(filePath,'utf8')));
}

function packageKey(ecosystem,name) {
  return `${normalizeEcosystem(ecosystem)}:${normalizeName(name)}`;
}

function buildPackageIndex(index) {
  validateIndex(index);
  const postings=new Map();
  index.advisories.forEach((adv,advisoryIndex)=>{
    adv.affected.forEach((item,affectedIndex)=>{
      const key=packageKey(item.ecosystem,item.name);
      if (!postings.has(key)) postings.set(key,[]);
      postings.get(key).push({advisoryIndex,affectedIndex});
    });
  });
  return postings;
}

function evaluateAffected(version,affected) {
  version=String(version||'').trim().replace(/^v(?=\d)/i,'');
  if (!version) return {state:'unknown',confidence:'none',reason:'组件没有精确版本'};
  if ((affected.versions||[]).some((x)=>String(x).replace(/^v(?=\d)/i,'')===version)) {
    return {state:'affected',confidence:'high',reason:`OSV affected.versions 明确包含 ${version}`,method:'exact-version'};
  }
  let comparable=false,unknownComparator=false;
  const exactGitEvidence=[];
  for (const interval of affected.intervals||[]) {
    if (String(interval.type||'').toUpperCase()==='GIT') {
      const verdict=evaluateGitBoundary(version,interval);
      if (verdict.state==='affected') return {...verdict,confidence:'high',interval};
      if (verdict.state==='not-affected') { comparable=true; exactGitEvidence.push(verdict.reason); continue; }
      unknownComparator=true;
      continue;
    }
    const hit=intervalContains(version,interval,affected.ecosystem);
    if (hit===null) { unknownComparator=true; continue; }
    comparable=true;
    if (hit) return {state:'affected',confidence:'high',reason:`${version} 落入 ${interval.type} affected range（${affected.ecosystem} 版本语义）`,method:'range',interval};
  }
  if (comparable&&!unknownComparator) {
    const fixed=[...new Set((affected.intervals||[]).map((x)=>x.fixed).filter(Boolean))];
    return {state:'not-affected',confidence:'high',reason:exactGitEvidence[0]||`${version} 未落入 advisory 的可比较 affected range`,method:exactGitEvidence.length?'git-boundary-exact':'range',fixedVersions:fixed.slice(0,12)};
  }
  if (unknownComparator) return {state:'unknown',confidence:'low',reason:'存在 affected range，但当前生态版本格式或 GIT ancestry 无法离线可靠比较'};
  return {state:'unknown',confidence:'low',reason:'advisory 未提供可用于当前组件版本的明确 versions/range'};
}

function matchAdvisoriesForTechStack(stack,index,options={}) {
  const available=Boolean(index?.schema===INDEX_SCHEMA&&Array.isArray(index.advisories));
  if (!available) return {indexAvailable:false,indexGeneratedAt:null,indexStats:null,matches:[],summary:{affected:0,notAffected:0,unknown:0},note:'尚未导入离线 OSV-compatible advisory 索引。'};
  const postings=buildPackageIndex(index);
  const matches=[];
  const seen=new Set();
  for (const component of stack?.components||[]) {
    if (!component?.version) continue;
    const refs=postings.get(packageKey(component.ecosystem,component.name))||[];
    for (const ref of refs) {
      const advisory=index.advisories[ref.advisoryIndex];
      const affected=advisory.affected[ref.affectedIndex];
      const verdict=evaluateAffected(component.version,affected);
      const key=`${advisory.id}|${component.ecosystem}|${component.name}|${component.version}`;
      if (seen.has(key)) continue; seen.add(key);
      matches.push({
        advisoryId:advisory.id,
        aliases:advisory.aliases,
        cves:advisory.cves,
        cwes:advisory.cwes||[],
        severity:advisory.severity||[],
        databaseSpecific:advisory.databaseSpecific||null,
        summary:advisory.summary,
        published:advisory.published,
        modified:advisory.modified,
        withdrawn:advisory.withdrawn,
        references:advisory.references,
        component:{ecosystem:component.ecosystem,name:component.name,version:component.version,purl:component.purl||null,cpe:component.cpe||null,sources:component.sources||[component.source].filter(Boolean)},
        applicability:verdict
      });
    }
  }
  const rank={affected:0,unknown:1,'not-affected':2};
  matches.sort((a,b)=>(rank[a.applicability.state]??9)-(rank[b.applicability.state]??9)||String(a.advisoryId).localeCompare(String(b.advisoryId)));
  const limited=matches.slice(0,Math.max(1,Math.min(Number(options.topK)||80,400)));
  const summary={affected:limited.filter((x)=>x.applicability.state==='affected').length,notAffected:limited.filter((x)=>x.applicability.state==='not-affected').length,unknown:limited.filter((x)=>x.applicability.state==='unknown').length};
  return {indexAvailable:true,indexGeneratedAt:index.generatedAt||null,indexStats:index.stats||null,matches:limited,summary,note:'affected/not-affected 仅基于本地 advisory 的明确 package + version/range 证据；PEP 440、Maven、Go/semver 使用各自版本语义，GIT range 没有 ancestry 时保持 unknown。'};
}

module.exports={
  INDEX_SCHEMA,normalizeEcosystem,compareVersion,intervalContains,rangesToIntervals,normalizeAdvisory,
  buildAdvisoryIndexFromDirectory,loadAdvisoryIndexFile,buildPackageIndex,evaluateAffected,matchAdvisoriesForTechStack
};
