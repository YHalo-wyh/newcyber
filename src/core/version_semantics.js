const QUALIFIER_ALIASES=Object.freeze({alpha:'a',beta:'b',pre:'rc',preview:'rc',cr:'rc',final:'',ga:'',release:'',rev:'post',r:'post'});

function cmp(a,b){return a===b?0:(a<b?-1:1);}
function stripV(value=''){return String(value||'').trim().replace(/^v(?=\d)/i,'');}

function parseSemver(value=''){
  const raw=stripV(value);
  const m=raw.match(/^(\d+(?:\.\d+){0,5})(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/);
  if(!m)return null;
  return {raw,release:m[1].split('.').map(Number),pre:m[2]?m[2].split(/[.-]/).map((x)=>/^\d+$/.test(x)?Number(x):x.toLowerCase()):[]};
}

function compareRelease(a,b){
  const len=Math.max(a.length,b.length);
  for(let i=0;i<len;i+=1){const d=cmp(a[i]??0,b[i]??0);if(d)return d;}
  return 0;
}

function compareIdentifiers(a,b){
  const len=Math.max(a.length,b.length);
  for(let i=0;i<len;i+=1){
    if(i>=a.length)return -1;
    if(i>=b.length)return 1;
    const x=a[i],y=b[i];
    if(x===y)continue;
    if(typeof x==='number'&&typeof y==='number')return cmp(x,y);
    if(typeof x==='number')return -1;
    if(typeof y==='number')return 1;
    return cmp(String(x),String(y));
  }
  return 0;
}

function compareSemver(a,b){
  const left=parseSemver(a),right=parseSemver(b);
  if(!left||!right)return null;
  const release=compareRelease(left.release,right.release);if(release)return release;
  if(!left.pre.length&&!right.pre.length)return 0;
  if(!left.pre.length)return 1;
  if(!right.pre.length)return -1;
  return compareIdentifiers(left.pre,right.pre);
}

function parsePep440(value=''){
  const raw=String(value||'').trim().toLowerCase().replace(/^v(?=\d)/,'');
  const m=raw.match(/^(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|rc|alpha|beta|pre|preview)[-_.]?(\d*)?)?(?:[-_.]?(post|rev|r)[-_.]?(\d*)?)?(?:[-_.]?dev[-_.]?(\d*)?)?(?:\+([a-z0-9][a-z0-9._-]*))?$/i);
  if(!m)return null;
  const preLabel=m[3]?(QUALIFIER_ALIASES[m[3]]??m[3]):null;
  const local=m[8]?m[8].split(/[._-]/).map((x)=>/^\d+$/.test(x)?Number(x):x):[];
  return {epoch:Number(m[1]||0),release:m[2].split('.').map(Number),pre:preLabel?[preLabel,Number(m[4]||0)]:null,post:m[5]?[Number(m[6]||0)]:null,dev:m[7]!==undefined?[Number(m[7]||0)]:null,local};
}

function pepStage(v){
  if(v.pre)return -2;
  if(v.dev&&!v.post)return -3;
  if(v.post)return 1;
  return 0;
}

function comparePep440(a,b){
  const left=parsePep440(a),right=parsePep440(b);if(!left||!right)return null;
  let d=cmp(left.epoch,right.epoch);if(d)return d;
  d=compareRelease(left.release,right.release);if(d)return d;
  d=cmp(pepStage(left),pepStage(right));if(d)return d;
  if(left.pre||right.pre){
    if(!left.pre)return 1;if(!right.pre)return -1;
    const rank={a:0,b:1,rc:2};
    d=cmp(rank[left.pre[0]]??9,rank[right.pre[0]]??9);if(d)return d;
    d=cmp(left.pre[1],right.pre[1]);if(d)return d;
    if(left.dev||right.dev){if(!left.dev)return 1;if(!right.dev)return -1;d=cmp(left.dev[0],right.dev[0]);if(d)return d;}
  }
  if(left.post||right.post){if(!left.post)return -1;if(!right.post)return 1;d=cmp(left.post[0],right.post[0]);if(d)return d;}
  if(!left.pre&&!left.post&&(left.dev||right.dev)){if(!left.dev)return 1;if(!right.dev)return -1;d=cmp(left.dev[0],right.dev[0]);if(d)return d;}
  if(!left.local.length&&!right.local.length)return 0;
  if(!left.local.length)return -1;if(!right.local.length)return 1;
  return compareIdentifiers(left.local,right.local);
}

const MAVEN_QUALIFIER_RANK=Object.freeze({alpha:-5,a:-5,beta:-4,b:-4,milestone:-3,m:-3,rc:-2,cr:-2,snapshot:-1,'':0,ga:0,final:0,release:0,sp:1});
function mavenTokens(value=''){
  const raw=String(value||'').trim().toLowerCase();
  if(!raw||!/^\d/.test(raw))return null;
  const expanded=raw.replace(/([0-9])([a-z])/g,'$1.$2').replace(/([a-z])([0-9])/g,'$1.$2');
  return expanded.split(/[.\-+_]/).filter((x)=>x!=='').map((x)=>/^\d+$/.test(x)?{n:Number(x)}:{q:QUALIFIER_ALIASES[x]??x});
}
function neutralMavenToken(token){return token?.n===0||token?.q===''||token===undefined;}
function compareMavenToken(a,b){
  if(a===undefined&&b===undefined)return 0;
  if(a===undefined)return neutralMavenToken(b)?0:(b.n!==undefined?-1:cmp(0,MAVEN_QUALIFIER_RANK[b.q]??2));
  if(b===undefined)return neutralMavenToken(a)?0:(a.n!==undefined?1:cmp(MAVEN_QUALIFIER_RANK[a.q]??2,0));
  if(a.n!==undefined&&b.n!==undefined)return cmp(a.n,b.n);
  if(a.n!==undefined)return 1;
  if(b.n!==undefined)return -1;
  const ar=MAVEN_QUALIFIER_RANK[a.q]??2,br=MAVEN_QUALIFIER_RANK[b.q]??2;
  return ar===br?(ar===2?cmp(a.q,b.q):0):cmp(ar,br);
}
function compareMaven(a,b){
  const left=mavenTokens(a),right=mavenTokens(b);if(!left||!right)return null;
  const len=Math.max(left.length,right.length);
  for(let i=0;i<len;i+=1){const d=compareMavenToken(left[i],right[i]);if(d)return d;}
  return 0;
}

function extractGoRevision(version=''){
  const raw=String(version||'').trim();
  const m=raw.match(/-(?:0\.)?\d{14}-([0-9a-f]{7,40})(?:\+incompatible)?$/i);
  return m?m[1].toLowerCase():null;
}

function compareGo(a,b){return compareSemver(stripV(a),stripV(b));}

function compareEcosystemVersion(a,b,ecosystem='',rangeType='ECOSYSTEM'){
  const type=String(rangeType||'ECOSYSTEM').toUpperCase();
  if(type==='SEMVER')return compareSemver(a,b);
  const eco=String(ecosystem||'').toLowerCase();
  if(eco==='pypi')return comparePep440(a,b);
  if(eco==='maven')return compareMaven(a,b);
  if(eco==='golang'||eco==='go')return compareGo(a,b);
  return compareSemver(a,b);
}

function commitMatches(candidate,boundary){
  const a=String(candidate||'').toLowerCase(),b=String(boundary||'').toLowerCase();
  if(!a||!b||a==='0'||b==='0')return false;
  return a===b||(a.length>=7&&b.startsWith(a))||(b.length>=7&&a.startsWith(b));
}

function evaluateGitBoundary(version,interval={}){
  const revision=extractGoRevision(version)||String(version||'').trim().toLowerCase();
  if(!/^[0-9a-f]{7,40}$/i.test(revision))return {state:'unknown',reason:'GIT range 需要可识别的 commit/revision；当前版本无法提取 revision'};
  if(interval.fixed&&commitMatches(revision,interval.fixed))return {state:'not-affected',reason:`revision 精确命中 fixed boundary ${interval.fixed}`,method:'git-boundary-exact'};
  if(interval.limit&&commitMatches(revision,interval.limit))return {state:'not-affected',reason:`revision 精确命中 exclusive limit ${interval.limit}`,method:'git-boundary-exact'};
  if(interval.lastAffected&&commitMatches(revision,interval.lastAffected))return {state:'affected',reason:`revision 精确命中 last_affected ${interval.lastAffected}`,method:'git-boundary-exact'};
  if(interval.introduced&&interval.introduced!=='0'&&commitMatches(revision,interval.introduced))return {state:'affected',reason:`revision 精确命中 introduced ${interval.introduced}`,method:'git-boundary-exact'};
  return {state:'unknown',reason:'已识别 GIT range，但离线索引没有提交图，不能仅按 commit 字符串推断 ancestry'};
}

module.exports={parseSemver,compareSemver,parsePep440,comparePep440,compareMaven,compareGo,extractGoRevision,compareEcosystemVersion,evaluateGitBoundary};
