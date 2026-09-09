const fsp=require('fs/promises');
const path=require('path');

const MAX_SOURCE_FILES=180;
const MAX_SOURCE_BYTES=384*1024;
const SOURCE_EXT=/\.(?:[cm]?js|jsx|ts|tsx|py|java|kt|kts|go|rs|rb|php|cs|c|cc|cpp|h|hpp)$/i;
const SKIP_PATH=/(^|\/)(?:node_modules|vendor|dist|build|coverage|\.git|\.venv|venv|target)(\/|$)/i;

function uniq(values=[]){return [...new Set(values.filter(Boolean).map(String))];}
function escapeRegex(value=''){return String(value).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');}
function safeRelative(value=''){return String(value||'').replace(/\\/g,'/').replace(/^\.\//,'');}

function sourceCandidates(analysis={}){
  return (analysis.files||[])
    .map((file)=>({file,path:safeRelative(file.path||file.name||'')}))
    .filter((item)=>item.path&&SOURCE_EXT.test(item.path)&&!SKIP_PATH.test(item.path))
    .slice(0,MAX_SOURCE_FILES);
}

function componentImportPatterns(component={}){
  const ecosystem=String(component.ecosystem||'').toLowerCase();
  const name=String(component.name||'').toLowerCase();
  if(!name)return [];
  const patterns=[];
  if(ecosystem==='npm'){
    const n=escapeRegex(name);
    patterns.push(new RegExp(`(?:require\\s*\\(\\s*|from\\s+|import\\s*)['\"]${n}(?:/[^'\"]*)?['\"]`,'i'));
  }else if(ecosystem==='pypi'){
    const mod=escapeRegex(name.replace(/[-.]+/g,'_'));
    patterns.push(new RegExp(`(?:^|\\n)\\s*(?:from\\s+${mod}(?:\\.|\\s)|import\\s+${mod}(?:\\.|\\s|$|,))`,'i'));
  }else if(ecosystem==='maven'){
    const [group,artifact]=name.split(':');
    if(group)patterns.push(new RegExp(`\\bimport\\s+${escapeRegex(group)}(?:\\.|;)`,'i'));
    if(artifact){
      const token=artifact.replace(/-(?:core|api|client|server|common|java)$/i,'');
      if(token.length>=4)patterns.push(new RegExp(`\\b${escapeRegex(token)}\\b`,'i'));
    }
  }else if(ecosystem==='golang'){
    patterns.push(new RegExp(`['\"]${escapeRegex(name)}(?:/[^'\"]*)?['\"]`,'i'));
  }else if(ecosystem==='cargo'){
    const crate=escapeRegex(name.replace(/-/g,'_'));
    patterns.push(new RegExp(`(?:\\buse\\s+${crate}(?:::|\\s)|\\bextern\\s+crate\\s+${crate}\\b)`,'i'));
  }else if(ecosystem==='gem'){
    patterns.push(new RegExp(`\\brequire\\s*\\(?\\s*['\"]${escapeRegex(name)}(?:/[^'\"]*)?['\"]`,'i'));
  }else if(ecosystem==='composer'){
    const tail=name.split('/').pop();
    if(tail&&tail.length>=4)patterns.push(new RegExp(`\\b${escapeRegex(tail)}\\b`,'i'));
  }else{
    const tokens=name.split(/[^a-z0-9]+/).filter((x)=>x.length>=4);
    if(tokens.length)patterns.push(new RegExp(`\\b${escapeRegex(tokens[0])}\\b`,'i'));
  }
  return patterns;
}

const SURFACE_PATTERNS=[
  /\b(?:app|router)\.(?:get|post|put|patch|delete|use|all)\s*\(/i,
  /\b(?:listen|createServer)\s*\(/i,
  /@(?:app|router)\.(?:route|get|post|put|delete)\b/i,
  /\b(?:Flask|FastAPI)\s*\(/i,
  /@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)\b/,
  /\b(?:HttpServlet|ServerSocket)\b/,
  /\bhttp\.(?:Handle|HandleFunc|ListenAndServe)\b/,
  /\bgrpc\.NewServer\b/,
  /\b(?:actix_web|axum|warp)::/,
  /\bTcpListener\b/
];

function surfaceHit(text=''){return SURFACE_PATTERNS.some((regex)=>regex.test(text));}
function scopeLooksDev(component={}){
  const raw=Array.isArray(component.scope)?component.scope.join(' '):String(component.scope||'');
  return /\b(?:dev|development|test|peer)\b/i.test(raw);
}

async function readSource(rootPath,relativePath){
  const root=path.resolve(rootPath);
  const full=path.resolve(root,relativePath);
  if(full!==root&&!full.startsWith(`${root}${path.sep}`))return null;
  try{
    const stat=await fsp.stat(full);
    if(!stat.isFile()||stat.size>MAX_SOURCE_BYTES)return null;
    return await fsp.readFile(full,'utf8');
  }catch{return null;}
}

function summarizeReachability(component,usageFiles,surfaceFiles){
  const usage=usageFiles.length>0;
  const surface=surfaceFiles.length>0;
  if(usage&&surface)return {state:'surface-co-located',confidence:'high',adjustment:12,reason:'在题目源码中观察到组件引用，且同一文件存在外部入口/监听面。'};
  if(usage)return {state:'source-reference',confidence:'medium',adjustment:7,reason:'在题目源码中观察到组件引用；尚未看到与外部入口同文件的确定证据。'};
  if(scopeLooksDev(component))return {state:'dev-dependency-only',confidence:'medium',adjustment:-10,reason:'当前只看到 dev/test 依赖声明，没有观察到题目源码直接引用。'};
  if((component.sources||[]).length||component.source)return {state:'dependency-only',confidence:'low',adjustment:-6,reason:'当前只看到依赖/版本证据，没有观察到题目源码直接引用；这不能证明漏洞不可达。'};
  return {state:'unknown',confidence:'low',adjustment:0,reason:'没有足够的源码引用证据判断组件在题目中的可达性。'};
}

async function analyzeComponentReachability(rootPath,analysis={},options={}){
  const candidates=analysis.vulnerabilityCandidates?.candidates||[];
  const files=sourceCandidates(analysis).slice(0,Math.max(1,Math.min(Number(options.maxFiles)||MAX_SOURCE_FILES,MAX_SOURCE_FILES)));
  const loaded=[];
  for(const item of files){
    const text=await readSource(rootPath,item.path);
    if(text!=null)loaded.push({path:item.path,text});
  }
  const results=[];
  for(const candidate of candidates){
    const component=candidate.component||{};
    const patterns=componentImportPatterns(component);
    const usageFiles=[]; const surfaceFiles=[]; let importHits=0; let surfaceHits=0;
    for(const file of loaded){
      if(!patterns.length)break;
      const hit=patterns.some((regex)=>regex.test(file.text));
      if(!hit)continue;
      usageFiles.push(file.path); importHits+=1;
      if(surfaceHit(file.text)){surfaceFiles.push(file.path);surfaceHits+=1;}
    }
    const summary=summarizeReachability(component,usageFiles,surfaceFiles);
    results.push({
      candidateId:candidate.id,
      primaryId:candidate.primaryId,
      component:{ecosystem:component.ecosystem||null,name:component.name||null,version:component.version||null},
      ...summary,
      usageFiles:uniq(usageFiles).slice(0,8),
      surfaceFiles:uniq(surfaceFiles).slice(0,8),
      importHits,
      surfaceHits
    });
  }
  const summary={
    total:results.length,
    surfaceCoLocated:results.filter((x)=>x.state==='surface-co-located').length,
    sourceReference:results.filter((x)=>x.state==='source-reference').length,
    dependencyOnly:results.filter((x)=>x.state==='dependency-only').length,
    devDependencyOnly:results.filter((x)=>x.state==='dev-dependency-only').length,
    unknown:results.filter((x)=>x.state==='unknown').length,
    scannedSourceFiles:loaded.length
  };
  return {schema:'newcyber.component-reachability.v1',summary,results,note:'这是保守的源码引用/入口共址证据，不是完整调用图。没有直接引用证据不等于漏洞不可达，尤其是传递依赖、反射、插件和框架自动装配场景。'};
}

module.exports={componentImportPatterns,surfaceHit,analyzeComponentReachability};
