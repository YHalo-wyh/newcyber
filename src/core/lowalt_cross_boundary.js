'use strict';

const MAX_TEXT=512*1024;
const MAX_EVENTS=4000;
const STAGES=['APP','GCS','FC','PHYSICAL'];
const CORRELATION_KEYS=['trace','trace_id','request','request_id','order','order_id','task','task_id','mission','mission_id','route','route_id','correlation','correlation_id','job','job_id'];

function asText(input){
  if(typeof input==='string') return input.slice(0,MAX_TEXT);
  if(!input||typeof input!=='object') return '';
  return String(input.text||input.evidence||input.workspaceSummary||'').slice(0,MAX_TEXT);
}

function normalizeScalar(value){
  if(value==null) return '';
  return String(value).trim().replace(/^['"]|['"]$/g,'');
}

function parseKv(line){
  const out={};
  const re=/([A-Za-z_][\w.-]*)\s*=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;]+)/g;
  let match;
  while((match=re.exec(line))) out[match[1].toLowerCase()]=normalizeScalar(match[2]);
  return out;
}

function firstValue(obj,keys){
  for(const key of keys){
    if(obj[key]!=null&&String(obj[key]).trim()!=='') return normalizeScalar(obj[key]);
  }
  return '';
}

function normalizeStage(value){
  const stage=String(value||'').trim().toUpperCase();
  if(STAGES.includes(stage)) return stage;
  if(/^(?:WEB|API|APP|BUSINESS|LOGISTICS)$/.test(stage)) return 'APP';
  if(/^(?:GROUND|GROUND_STATION|STATION)$/.test(stage)) return 'GCS';
  if(/^(?:FLIGHT_CONTROLLER|AUTOPILOT|PX4|ARDUPILOT)$/.test(stage)) return 'FC';
  if(/^(?:FLIGHT|VEHICLE|LOG|OUTCOME|EFFECT)$/.test(stage)) return 'PHYSICAL';
  return '';
}

function inferStage(raw,obj){
  const explicit=normalizeStage(firstValue(obj,['stage','layer','component','surface']));
  if(explicit) return explicit;
  if(/\b(?:GET|POST|PUT|PATCH|DELETE)\s+\/[\w/?&=.-]+/i.test(raw)||/\b(?:jwt|session|authorization|idor|bola|order|logistics|delivery|payment|tenant|dispatch api|rest|graphql)\b/i.test(raw)||/订单|物流|越权|调度接口/.test(raw)) return 'APP';
  if(/\b(?:ground.?station|\bgcs\b|mission\.json|planner|operator console|telemetry bridge|dispatch bridge)\b/i.test(raw)||/地面站|任务规划|操作员终端/.test(raw)) return 'GCS';
  if(/\b(?:MAVLink|MISSION_ITEM(?:_INT)?|MISSION_COUNT|MISSION_CURRENT|PARAM_SET|PARAM_VALUE|COMMAND_LONG|COMMAND_ACK|SET_POSITION_TARGET|SERIAL_CONTROL|sysid|compid|PX4|ArduPilot)\b/i.test(raw)||/飞控|航点下发|参数写入/.test(raw)) return 'FC';
  if(/\b(?:ULog|DataFlash|flight.?log|vehicle.?state|position changed|mission changed|mode changed|armed|disarmed|altitude|latitude|longitude|GPS_RAW_INT|GLOBAL_POSITION_INT)\b/i.test(raw)||/飞行日志|位置变化|航线变化|飞行状态/.test(raw)) return 'PHYSICAL';
  return 'UNKNOWN';
}

function parseTime(value){
  if(value==null||value==='') return null;
  if(Number.isFinite(Number(value))) return Number(value);
  const parsed=Date.parse(String(value));
  return Number.isFinite(parsed)?parsed:null;
}

function extractCorrelations(obj,raw){
  const tokens=[];
  for(const key of CORRELATION_KEYS){
    const value=normalizeScalar(obj[key]);
    if(!value) continue;
    tokens.push({key,value,token:`${key}:${value}`,strength:/^(?:trace|trace_id|correlation|correlation_id|request_id)$/.test(key)?3:2});
    if(String(value).length>=3&&!/^\d{1,2}$/.test(String(value))) tokens.push({key:'value',value,token:`value:${value}`,strength:1});
  }
  const inline=/\b(?:trace|request|order|task|mission|route)[#:=/-]([A-Za-z0-9_.:-]{3,})\b/gi;
  let match;
  while((match=inline.exec(raw))) tokens.push({key:'inline',value:match[1],token:`value:${match[1]}`,strength:1});
  const seen=new Set();
  return tokens.filter((item)=>{if(seen.has(item.token)) return false; seen.add(item.token); return true;});
}

function authWeak(raw,obj){
  const value=firstValue(obj,['auth','authorization','authorized','permission','acl','session_state','security']).toLowerCase();
  if(/^(?:none|missing|false|0|off|disabled|bypass|idor|bola|unauthorized|forged|weak)$/i.test(value)) return true;
  return /\b(?:idor|bola|authorization bypass|auth bypass|unauthorized|forged token|missing auth)\b/i.test(raw)||/越权|未授权|绕过鉴权|鉴权缺失/.test(raw);
}

function authStrong(raw,obj){
  const value=firstValue(obj,['auth','authorization','authorized','permission','security']).toLowerCase();
  return /^(?:ok|true|1|authorized|signed|verified|enforced)$/i.test(value)||/signature=(?:ok|valid)|auth=(?:ok|signed)|authorization=(?:ok|enforced)/i.test(raw);
}

function accepted(raw,obj){
  const value=firstValue(obj,['status','result','ack','response','http_status']).toLowerCase();
  if(/^(?:ok|accepted|success|200|201|202|204|0|true)$/i.test(value)) return true;
  return /\b(?:accepted|success|COMMAND_ACK.*(?:accepted|result=0)|HTTP\/\S+ 2\d\d)\b/i.test(raw)||/接受|成功|已生效/.test(raw);
}

function parseLine(line,index){
  const raw=String(line||'').trim();
  if(!raw) return null;
  let obj={};
  if(raw.startsWith('{')&&raw.endsWith('}')){
    try{
      const parsed=JSON.parse(raw);
      if(parsed&&typeof parsed==='object'&&!Array.isArray(parsed)) for(const [k,v] of Object.entries(parsed)) obj[String(k).toLowerCase()]=v;
    }catch{}
  }
  if(!Object.keys(obj).length) obj=parseKv(raw);
  const stage=inferStage(raw,obj);
  const ts=parseTime(firstValue(obj,['ts','timestamp','time']));
  const correlations=extractCorrelations(obj,raw);
  const actor=firstValue(obj,['actor','user','subject','src','sender','operator','client','service']);
  const target=firstValue(obj,['target','dst','object','vehicle','uav','drone','sysid']);
  const action=firstValue(obj,['action','op','event','type','msg','message','method']);
  return {index,raw,fields:obj,stage,ts,correlations,actor,target,action,authWeak:authWeak(raw,obj),authStrong:authStrong(raw,obj),accepted:accepted(raw,obj)};
}

function normalizeEvents(input){
  const supplied=input&&typeof input==='object'&&Array.isArray(input.events)?input.events:[];
  const rows=[];
  for(const item of supplied.slice(0,MAX_EVENTS)){
    const line=typeof item==='string'?item:Object.entries(item||{}).map(([k,v])=>`${k}=${typeof v==='string'&&/\s/.test(v)?JSON.stringify(v):v}`).join(' ');
    const parsed=parseLine(line,rows.length); if(parsed) rows.push(parsed);
  }
  if(!rows.length){
    for(const line of asText(input).split(/\r?\n/).slice(0,MAX_EVENTS)){
      const parsed=parseLine(line,rows.length); if(parsed) rows.push(parsed);
    }
  }
  return rows;
}

function tokenGroups(events){
  const groups=new Map();
  for(const event of events){
    for(const item of event.correlations){
      if(!groups.has(item.token)) groups.set(item.token,{token:item.token,key:item.key,value:item.value,strength:item.strength,events:[]});
      const group=groups.get(item.token); group.strength=Math.max(group.strength,item.strength); group.events.push(event);
    }
  }
  return [...groups.values()];
}

function stageIndex(stage){return STAGES.indexOf(stage);}

function buildPath(group){
  const ordered=group.events.filter((e)=>stageIndex(e.stage)>=0).sort((a,b)=>a.index-b.index);
  const stageFirst=new Map();
  for(const event of ordered) if(!stageFirst.has(event.stage)) stageFirst.set(event.stage,event);
  const stages=STAGES.filter((stage)=>stageFirst.has(stage));
  if(stages.length<2) return null;
  const edges=[];
  let previous=null;
  for(const stage of STAGES){
    const event=stageFirst.get(stage); if(!event) continue;
    if(previous){
      edges.push({from:previous.stage,to:event.stage,correlation:group.token,confidence:group.strength===3?'high':group.strength===2?'medium':'supporting',evidence:[previous.raw,event.raw]});
    }
    previous=event;
  }
  const firstIndex=Math.min(...ordered.map((e)=>e.index));
  const lastIndex=Math.max(...ordered.map((e)=>e.index));
  const monotonic=ordered.every((e,i)=>i===0||e.index>=ordered[i-1].index);
  const score=(stages.length*20)+(group.strength*8)+(stageFirst.has('APP')?8:0)+(stageFirst.has('PHYSICAL')?10:0)+(monotonic?4:0);
  return {id:`path-${group.token}`,correlation:group.token,correlationKey:group.key,correlationValue:group.value,stages,coverage:`${stages.length}/4`,score,edges,events:ordered.map((e)=>({index:e.index,stage:e.stage,raw:e.raw,authWeak:e.authWeak,authStrong:e.authStrong,accepted:e.accepted})),firstIndex,lastIndex};
}

function addFinding(findings,id,severity,title,path,evidence,why,nextCheck){
  findings.push({id,severity,state:'candidate',title,path:path?.id||null,correlation:path?.correlation||null,evidence:[...new Set(evidence.filter(Boolean))].slice(0,12),why,nextCheck});
}

function analyzeCrossBoundaryFlow(input,options={}){
  const events=normalizeEvents(input);
  const groups=tokenGroups(events);
  const paths=groups.map(buildPath).filter(Boolean).sort((a,b)=>b.score-a.score);
  const findings=[];

  for(const path of paths){
    const app=path.events.filter((e)=>e.stage==='APP');
    const gcs=path.events.filter((e)=>e.stage==='GCS');
    const fc=path.events.filter((e)=>e.stage==='FC');
    const physical=path.events.filter((e)=>e.stage==='PHYSICAL');
    const weakApp=app.find((e)=>e.authWeak);
    const acceptedFc=fc.find((e)=>e.accepted||e.authWeak);
    if(weakApp&&gcs.length&&fc.length){
      addFinding(findings,'cross-boundary-auth-flow','high','业务侧授权弱点关联到飞控控制链',path,[weakApp.raw,...gcs.map((e)=>e.raw),...fc.map((e)=>e.raw)],'同一关联标识下，APP 侧存在显式未授权/越权证据，并继续出现 GCS 与 FC 事件。','复核业务请求是否真的驱动该任务/航线；用无权限主体与合法主体做对照，并在 FC 侧核对任务/参数变化。');
    }
    const weakGcs=gcs.find((e)=>e.authWeak);
    if(gcs.length&&acceptedFc&&(weakGcs||fc.some((e)=>e.authWeak))){
      addFinding(findings,'cross-boundary-control-acceptance','high','GCS → FC 控制边界存在未认证接受候选',path,[...(weakGcs?[weakGcs.raw]:[]),...fc.map((e)=>e.raw)],'同一关联链中出现 GCS/FC 未认证或 unsigned 证据，并伴随 FC 接受/控制事件。','验证飞控是否实际拒绝未签名/未授权源；修复后复放相同消息应得到明确拒绝或无状态变化。');
    }
    if(app.length&&fc.length&&physical.length){
      addFinding(findings,'business-to-physical-impact','high','业务入口关联到飞行状态影响',path,[...app.map((e)=>e.raw),...fc.map((e)=>e.raw),...physical.map((e)=>e.raw)],'同一关联标识覆盖 APP、FC 与 PHYSICAL，已经具备“业务动作 → 控制 → 飞行结果”的证据骨架。','仍需确认因果而非时间巧合：做一次受控重放/负例，证明对应业务输入能够稳定改变同一飞行状态。');
    }
  }

  const dedup=[]; const seen=new Set();
  for(const finding of findings){
    const key=`${finding.id}|${finding.correlation||''}`; if(seen.has(key)) continue; seen.add(key); dedup.push(finding);
  }

  const stageEvidence={};
  for(const stage of [...STAGES,'UNKNOWN']){
    stageEvidence[stage]=events.filter((e)=>e.stage===stage).slice(0,50).map((e)=>({index:e.index,raw:e.raw,correlations:e.correlations.map((c)=>c.token),authWeak:e.authWeak,accepted:e.accepted}));
  }
  const observedStages=STAGES.filter((stage)=>stageEvidence[stage].length>0);
  const best=paths[0]||null;
  const gaps=[];
  if(observedStages.length>=2&&!best) gaps.push('多个业务/控制层已有证据，但没有共享 trace / request / order / task / mission / route 等关联标识，暂不连边。');
  if(best){
    for(let i=0;i<STAGES.length-1;i++){
      const left=STAGES[i],right=STAGES[i+1];
      if(best.stages.includes(left)&&best.stages.includes(right)) continue;
      if(best.stages.includes(left)&&!best.stages.includes(right)) gaps.push(`${left} → ${right} 缺少同一关联标识下的下一跳证据。`);
    }
  }
  if(!stageEvidence.APP.length) gaps.push('缺 APP 入口/身份/订单/调度证据。');
  if(!stageEvidence.GCS.length) gaps.push('缺 GCS/任务规划/桥接证据。');
  if(!stageEvidence.FC.length) gaps.push('缺 MAVLink/飞控控制或 ACK 证据。');
  if(!stageEvidence.PHYSICAL.length) gaps.push('缺飞行日志/状态变化证据，无法证明物理或业务影响。');

  const nodes=[];
  for(const stage of STAGES){
    nodes.push({id:stage,label:stage==='APP'?'业务系统 / API':stage==='GCS'?'地面站 / 调度桥':stage==='FC'?'飞控 / MAVLink':'飞行状态 / 日志',evidenceCount:stageEvidence[stage].length});
  }
  const edges=[];
  for(const path of paths.slice(0,20)) for(const edge of path.edges){
    const key=`${edge.from}->${edge.to}|${edge.correlation}`;
    if(edges.some((e)=>e.key===key)) continue;
    edges.push({key,...edge});
  }

  return {
    schema:'newcyber.lowalt-cross-boundary.v1',
    mode:'deterministic-cross-boundary-flow',
    summary:{events:events.length,observedStages:observedStages.length,linkedPaths:paths.length,candidates:dedup.length,bestCoverage:best?.coverage||'0/4'},
    stages:STAGES.map((stage)=>({id:stage,evidence:stageEvidence[stage]})),
    graph:{nodes,edges},
    paths:paths.slice(0,40),findings:dedup,gaps,
    unlinkedEvidence:stageEvidence.UNKNOWN,
    notes:[
      '只有共享关联标识的跨层证据才会被连成路径；仅仅“APP/GCS/FC 都出现过”不等于存在攻击链。',
      '自动输出始终是 candidate，不把时间先后关系直接当作因果关系。',
      'FULL 证据链应至少包含入口身份/授权、桥接/调度、飞控接受结果，以及飞行日志或状态对照。'
    ],
    options:{strictCorrelation:options.strictCorrelation!==false}
  };
}

module.exports={parseLine,normalizeEvents,analyzeCrossBoundaryFlow};
