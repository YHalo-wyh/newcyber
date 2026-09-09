const fsp=require('fs/promises');
const path=require('path');

const MAX_SOURCE_FILES=180;
const MAX_SOURCE_BYTES=384*1024;
const SOURCE_EXT=/\.(?:[cm]?js|jsx|ts|tsx|py|java|kt|kts|go|rs|rb|php|cs|c|cc|cpp|h|hpp)$/i;
const SKIP_PATH=/(^|\/)(?:node_modules|vendor|dist|build|coverage|\.git|\.venv|venv|target)(\/|$)/i;
const FLOW_WINDOW=36;

function escRe(value=''){return String(value).replace(/[.*+?^${}()|[\]\\]/g,'\\$&');}
function uniq(values=[]){return [...new Set(values.filter(Boolean).map(String))];}
function rel(value=''){return String(value||'').replace(/\\/g,'/').replace(/^\.\//,'');}
function lineText(value=''){return String(value||'').trim().replace(/\s+/g,' ').slice(0,260);}

function sourceFiles(analysis={}){
  return (analysis.files||[]).map((file)=>rel(file.path||file.name||''))
    .filter((p)=>p&&SOURCE_EXT.test(p)&&!SKIP_PATH.test(p)).slice(0,MAX_SOURCE_FILES);
}

async function readSource(rootPath,relativePath){
  const root=path.resolve(rootPath); const full=path.resolve(root,relativePath);
  if(full!==root&&!full.startsWith(`${root}${path.sep}`))return null;
  try{const stat=await fsp.stat(full);if(!stat.isFile()||stat.size>MAX_SOURCE_BYTES)return null;return await fsp.readFile(full,'utf8');}catch{return null;}
}

function addBindings(out,values=[]){for(const value of values){const v=String(value||'').trim();if(/^[A-Za-z_$][\w$]*$/.test(v))out.add(v);}}

function componentBindings(component={},text=''){
  const ecosystem=String(component.ecosystem||'').toLowerCase();
  const rawName=String(component.name||'');
  const name=rawName.toLowerCase();
  const out=new Set();
  if(!name)return [];

  if(ecosystem==='npm'){
    const n=escRe(rawName);
    let m;
    const requireRe=new RegExp(`(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*require\\s*\\(\\s*['\"]${n}(?:/[^'\"]*)?['\"]\\s*\\)`,'g');
    while((m=requireRe.exec(text)))addBindings(out,[m[1]]);
    const importRe=new RegExp(`import\\s+(?:\\*\\s+as\\s+)?([A-Za-z_$][\\w$]*)\\s+from\\s+['\"]${n}(?:/[^'\"]*)?['\"]`,'g');
    while((m=importRe.exec(text)))addBindings(out,[m[1]]);
    const namedImport=new RegExp(`import\\s*\\{([^}]+)\\}\\s*from\\s*['\"]${n}(?:/[^'\"]*)?['\"]`,'g');
    while((m=namedImport.exec(text)))addBindings(out,m[1].split(',').map((x)=>x.trim().split(/\\s+as\\s+/i).pop()));
    const namedRequire=new RegExp(`(?:const|let|var)\\s*\\{([^}]+)\\}\\s*=\\s*require\\s*\\(\\s*['\"]${n}(?:/[^'\"]*)?['\"]\\s*\\)`,'g');
    while((m=namedRequire.exec(text)))addBindings(out,m[1].split(',').map((x)=>x.trim().split(/\\s*:\\s*/).pop()));
  }else if(ecosystem==='pypi'){
    const mod=rawName.replace(/[-.]+/g,'_'); const n=escRe(mod); let m;
    const importRe=new RegExp(`(?:^|\\n)\\s*import\\s+${n}(?:\\.[\\w.]+)?(?:\\s+as\\s+([A-Za-z_]\\w*))?`,'g');
    while((m=importRe.exec(text)))addBindings(out,[m[1]||mod.split('.')[0]]);
    const fromRe=new RegExp(`(?:^|\\n)\\s*from\\s+${n}(?:\\.[\\w.]+)?\\s+import\\s+([^\\n#]+)`,'g');
    while((m=fromRe.exec(text)))addBindings(out,m[1].split(',').map((x)=>x.trim().split(/\\s+as\\s+/i).pop()));
  }else if(ecosystem==='golang'){
    const n=escRe(rawName); let m;
    const importAlias=new RegExp(`(?:^|\\n)\\s*([A-Za-z_]\\w*)\\s+['\"]${n}(?:/[^'\"]*)?['\"]`,'g');
    while((m=importAlias.exec(text)))addBindings(out,[m[1]]);
    if(new RegExp(`['\"]${n}(?:/[^'\"]*)?['\"]`).test(text))addBindings(out,[rawName.split('/').pop().replace(/[^A-Za-z0-9_]/g,'')]);
  }else if(ecosystem==='cargo'){
    const crate=rawName.replace(/-/g,'_'); const n=escRe(crate); let m;
    if(new RegExp(`\\b(?:use|extern\\s+crate)\\s+${n}\\b`).test(text))addBindings(out,[crate]);
    const useRe=new RegExp(`\\buse\\s+${n}::(?:\\{([^}]+)\\}|([A-Za-z_]\\w*))`,'g');
    while((m=useRe.exec(text)))addBindings(out,m[1]?m[1].split(',').map((x)=>x.trim().split(/\\s+as\\s+/).pop()):[m[2]]);
  }else if(ecosystem==='maven'){
    const group=rawName.split(':')[0]; if(group){
      const re=new RegExp(`\\bimport\\s+${escRe(group)}[\\w.*]*\\.([A-Za-z_$][\\w$]*)\\s*;`,'g'); let m;
      while((m=re.exec(text)))addBindings(out,[m[1]]);
    }
  }else if(ecosystem==='gem'){
    const token=rawName.replace(/[-.]+/g,'_'); if(new RegExp(`\\brequire\\s*\\(?\\s*['\"]${escRe(rawName)}`).test(text))addBindings(out,[token,rawName.split('-').map((x)=>x[0]?.toUpperCase()+x.slice(1)).join('')]);
  }else if(ecosystem==='composer'){
    const token=rawName.split('/').pop().replace(/[-.]+/g,''); if(token.length>=3)addBindings(out,[token]);
  }else{
    addBindings(out,rawName.split(/[^A-Za-z0-9_$]+/).filter((x)=>x.length>=3).slice(-2));
  }
  return [...out].slice(0,16);
}

const EXTERNAL_SOURCE_PATTERNS=[
  {id:'http-request',re:/\b(?:req|request|ctx)\.(?:body|query|params|headers|cookies|files?|input|form|json|data)\b/i},
  {id:'web-framework',re:/\b(?:request\.(?:args|form|json|data|values|files)|params\s*\[|@RequestParam|@PathVariable|Request\.Query|Request\.Form|Request\.Body|\$_(?:GET|POST|REQUEST|COOKIE|FILES))\b/i},
  {id:'body-read',re:/\b(?:FormValue|PostFormValue|ReadAll\s*\(\s*r\.Body|getParameter|getInputStream|php:\/\/input)\b/i},
  {id:'cli-input',re:/\b(?:process\.argv|sys\.argv|os\.Args|ARGV\b|Console\.ReadLine|\binput\s*\(|\bgets\b|\bargv\s*\[)/i},
  {id:'socket-input',re:/\b(?:recv|recvfrom|read)\s*\([^\n;]*(?:sock|fd|client|conn)/i}
];
const SURFACE_LINE_PATTERNS=[
  /\b(?:app|router)\.(?:get|post|put|patch|delete|use|all)\s*\(/i,
  /@(?:app|router)\.(?:route|get|post|put|delete)\b/i,
  /@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)\b/,
  /\bhttp\.(?:Handle|HandleFunc)\b/,
  /\b(?:Flask|FastAPI)\s*\(/,
  /\b(?:actix_web|axum|warp)::/,
  /\b(?:ServerSocket|TcpListener)\b/
];

function sourceKind(line=''){for(const p of EXTERNAL_SOURCE_PATTERNS)if(p.re.test(line))return p.id;return null;}
function isSurfaceLine(line=''){return SURFACE_LINE_PATTERNS.some((r)=>r.test(line));}
function wordUsed(line,name){return new RegExp(`\\b${escRe(name)}\\b`).test(line);}

function sourceVariable(line=''){
  if(!sourceKind(line))return null;
  const patterns=[
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*/, /\b([A-Za-z_][\w]*)\s*:=\s*/,
    /^\s*([A-Za-z_$][\w$]*)\s*=\s*/, /(?:String|int|long|var|auto)\s+([A-Za-z_$][\w$]*)\s*=\s*/
  ];
  for(const re of patterns){const m=line.match(re);if(m)return m[1];}
  const ann=line.match(/@(?:RequestParam|PathVariable)[^\n,)]*[,)]?\s*(?:final\s+)?[\w<>?,.\[\]]+\s+([A-Za-z_$][\w$]*)/);
  return ann?.[1]||null;
}

function routeParameterVariables(lines,index){
  const start=Math.max(0,index-FLOW_WINDOW); let surface=-1;
  for(let i=index;i>=start;i-=1){if(isSurfaceLine(lines[i])){surface=i;break;}}
  if(surface<0)return [];
  const vars=new Set();
  for(let i=surface;i<=Math.min(index,surface+5);i+=1){
    const line=lines[i]||'';
    const py=line.match(/\bdef\s+\w+\s*\(([^)]*)\)/);
    if(py)for(const part of py[1].split(',')){const v=part.trim().match(/^([A-Za-z_]\w*)\s*(?::|=|$)/)?.[1];if(v&&!['self','request','req'].includes(v))vars.add(v);}
    let m; const java=/@(?:RequestParam|PathVariable)[^,)]*[,)]?\s*(?:final\s+)?[\w<>?,.\[\]]+\s+([A-Za-z_$][\w$]*)/g;
    while((m=java.exec(line)))vars.add(m[1]);
  }
  return [...vars];
}

function callMatches(line='',bindings=[]){
  if(/^\s*(?:import|from|use|extern\s+crate|require\s*\()/i.test(line))return null;
  for(const binding of bindings){
    const member=new RegExp(`\\b${escRe(binding)}\\s*(?:\\.|::|->)\\s*([A-Za-z_$][\\w$]*)\\s*\\(`);
    const m=line.match(member); if(m)return {binding,api:m[1]};
    const direct=new RegExp(`\\b${escRe(binding)}\\s*\\(`); if(direct.test(line))return {binding,api:binding};
  }
  return null;
}

function oneHopVars(lines,start,end,seed){
  const vars=new Set([seed]);
  for(let i=start;i<=end;i+=1){
    const line=lines[i]||'';
    const m=line.match(/(?:const|let|var\s+)?([A-Za-z_$][\w$]*)\s*(?::=|=)\s*([A-Za-z_$][\w$]*)\b/);
    if(m&&vars.has(m[2]))vars.add(m[1]);
  }
  return vars;
}

function flowForCall(lines,callIndex,call){
  const callLine=lines[callIndex]||'';
  const directKind=sourceKind(callLine);
  if(directKind)return {kind:'direct',sourceKind:directKind,sourceLine:callIndex+1,callLine:callIndex+1,variable:null};
  const start=Math.max(0,callIndex-FLOW_WINDOW);
  for(let i=callIndex-1;i>=start;i-=1){
    const variable=sourceVariable(lines[i]||''); if(!variable)continue;
    const propagated=oneHopVars(lines,i+1,callIndex-1,variable);
    for(const candidate of propagated){
      if(wordUsed(callLine,candidate))return {kind:candidate===variable?'local-variable':'one-hop',sourceKind:sourceKind(lines[i]),sourceLine:i+1,callLine:callIndex+1,variable:candidate,originVariable:variable};
    }
  }
  for(const variable of routeParameterVariables(lines,callIndex)){
    if(wordUsed(callLine,variable))return {kind:'route-parameter',sourceKind:'route-parameter',sourceLine:null,callLine:callIndex+1,variable};
  }
  return null;
}

function summarize(bindings,apiCalls,flows,nearSurface){
  if(flows.length)return {state:'entry-to-api',confidence:'high',adjustment:16,reason:'观察到外部输入直接或经短局部变量传播进入该组件 API 调用。'};
  if(apiCalls.length&&nearSurface)return {state:'surface-to-api-nearby',confidence:'medium',adjustment:6,reason:'观察到组件 API 调用，且附近存在外部入口；尚未建立输入值到调用参数的确定传播。'};
  if(apiCalls.length)return {state:'api-call-only',confidence:'medium',adjustment:2,reason:'观察到组件 API 调用，但没有看到外部输入进入调用参数。'};
  if(bindings.length)return {state:'import-only',confidence:'low',adjustment:-2,reason:'观察到组件绑定/import，但未观察到组件 API 调用。'};
  return {state:'unknown',confidence:'low',adjustment:0,reason:'没有足够证据定位组件 API 调用点。'};
}

async function analyzeVulnerableApiFlow(rootPath,analysis={},options={}){
  const limit=Math.max(1,Math.min(Number(options.maxFiles)||MAX_SOURCE_FILES,MAX_SOURCE_FILES));
  const loaded=[];
  for(const file of sourceFiles(analysis).slice(0,limit)){const text=await readSource(rootPath,file);if(text!=null)loaded.push({path:file,text,lines:text.split(/\r?\n/)});}
  const results=[];
  for(const candidate of analysis.vulnerabilityCandidates?.candidates||[]){
    const component=candidate.component||{}; const apiCalls=[]; const flows=[]; const bindingFiles=[]; const surfaceFiles=[]; const allBindings=new Set();
    for(const file of loaded){
      const bindings=componentBindings(component,file.text); if(!bindings.length)continue;
      bindingFiles.push(file.path); bindings.forEach((x)=>allBindings.add(x));
      const surfaces=[]; file.lines.forEach((line,i)=>{if(isSurfaceLine(line))surfaces.push(i);});
      for(let i=0;i<file.lines.length;i+=1){
        const hit=callMatches(file.lines[i],bindings); if(!hit)continue;
        const near=surfaces.some((s)=>Math.abs(s-i)<=FLOW_WINDOW); if(near)surfaceFiles.push(file.path);
        const item={file:file.path,line:i+1,binding:hit.binding,api:hit.api,snippet:lineText(file.lines[i]),nearSurface:near};
        apiCalls.push(item);
        const flow=flowForCall(file.lines,i,hit); if(flow)flows.push({...flow,file:file.path,api:hit.api,callSnippet:item.snippet,sourceSnippet:flow.sourceLine?lineText(file.lines[flow.sourceLine-1]):null});
        if(apiCalls.length>=80)break;
      }
    }
    const nearSurface=apiCalls.some((x)=>x.nearSurface); const summary=summarize([...allBindings],apiCalls,flows,nearSurface);
    results.push({candidateId:candidate.id,primaryId:candidate.primaryId,component:{ecosystem:component.ecosystem||null,name:component.name||null,version:component.version||null},...summary,bindings:uniq([...allBindings]).slice(0,12),bindingFiles:uniq(bindingFiles).slice(0,8),surfaceFiles:uniq(surfaceFiles).slice(0,8),apiCalls:apiCalls.slice(0,12),flows:flows.slice(0,8)});
  }
  return {schema:'newcyber.vulnerable-api-flow.v1',summary:{total:results.length,entryToApi:results.filter((x)=>x.state==='entry-to-api').length,surfaceNearby:results.filter((x)=>x.state==='surface-to-api-nearby').length,apiCallOnly:results.filter((x)=>x.state==='api-call-only').length,importOnly:results.filter((x)=>x.state==='import-only').length,unknown:results.filter((x)=>x.state==='unknown').length,scannedSourceFiles:loaded.length},results,note:'这是有界的局部静态传播证据：只跟踪直接输入、路由参数和最多一跳局部变量。它不是跨函数/跨模块调用图；反射、插件、依赖注入、框架装配和传递调用需要人工继续确认。'};
}

module.exports={componentBindings,sourceKind,analyzeVulnerableApiFlow};
