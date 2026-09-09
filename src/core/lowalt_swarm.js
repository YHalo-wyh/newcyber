'use strict';

const MAX_TEXT=512*1024;
const MAX_EVENTS=4000;
const DEFAULT_TIME_SKEW_MS=2000;

const TYPE_ALIASES=Object.freeze({
  join:'JOIN',admit:'JOIN',member_join:'JOIN',hello:'JOIN',discovery:'JOIN',
  heartbeat:'HEARTBEAT',status:'STATUS',state:'STATUS',
  leader:'LEADER',elect:'LEADER',election:'LEADER',leader_announce:'LEADER',
  assign:'TASK_ASSIGN',task_assign:'TASK_ASSIGN',assignment:'TASK_ASSIGN',dispatch:'TASK_ASSIGN',
  task_update:'TASK_UPDATE',task_status:'TASK_UPDATE',
  sync:'TIME_SYNC',time_sync:'TIME_SYNC',clock_sync:'TIME_SYNC',
  broadcast:'BROADCAST',multicast:'BROADCAST',message:'MESSAGE'
});

function asText(input){
  if(typeof input==='string') return input.slice(0,MAX_TEXT);
  if(!input||typeof input!=='object') return '';
  return String(input.text||input.evidence||input.workspaceSummary||'').slice(0,MAX_TEXT);
}

function normalizeScalar(value){
  if(value==null) return '';
  return String(value).trim().replace(/^['"]|['"]$/g,'');
}

function firstValue(obj,keys){
  for(const key of keys){
    if(obj[key]!=null && String(obj[key]).trim()!=='') return normalizeScalar(obj[key]);
  }
  return '';
}

function parseKv(line){
  const out={};
  const re=/([A-Za-z_][\w.-]*)\s*=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;]+)/g;
  let match;
  while((match=re.exec(line))) out[match[1].toLowerCase()]=normalizeScalar(match[2]);
  return out;
}

function parseLine(line,index){
  const raw=String(line||'').trim();
  if(!raw) return null;
  let obj={};
  if(raw.startsWith('{')&&raw.endsWith('}')){
    try{
      const parsed=JSON.parse(raw);
      if(parsed&&typeof parsed==='object'&&!Array.isArray(parsed)){
        for(const [key,value] of Object.entries(parsed)) obj[String(key).toLowerCase()]=value;
      }
    }catch{}
  }
  if(!Object.keys(obj).length) obj=parseKv(raw);

  const typeRaw=firstValue(obj,['type','event','msg','message','action','op']).toLowerCase();
  let type=TYPE_ALIASES[typeRaw]||String(typeRaw||'').toUpperCase();
  if(!type){
    if(/task[_ -]?assign|任务分配|dispatch/i.test(raw)) type='TASK_ASSIGN';
    else if(/leader|选主|主节点/i.test(raw)) type='LEADER';
    else if(/time[_ -]?sync|clock|时钟同步/i.test(raw)) type='TIME_SYNC';
    else if(/join|admit|成员加入|节点加入/i.test(raw)) type='JOIN';
    else if(/broadcast|multicast|广播|组播/i.test(raw)) type='BROADCAST';
    else type='MESSAGE';
  }

  const sender=firstValue(obj,['src','sender','member','member_id','node','node_id','uav','drone','peer']);
  const target=firstValue(obj,['dst','target','receiver','to','peer_target']);
  const role=firstValue(obj,['role','member_role']).toLowerCase();
  const task=firstValue(obj,['task','task_id','job','job_id']);
  const seqRaw=firstValue(obj,['seq','sequence','sequence_id','counter']);
  const seq=seqRaw!==''&&Number.isFinite(Number(seqRaw))?Number(seqRaw):null;
  const term=firstValue(obj,['term','epoch','generation','view']);
  const auth=firstValue(obj,['auth','authenticated','signed','signature','security']).toLowerCase();
  const address=firstValue(obj,['addr','address','ip','mac','endpoint']);
  const session=firstValue(obj,['session','session_id','key_id','key','identity_key']);
  const route=firstValue(obj,['route','mission','mission_id','formation','formation_id']);
  const state=firstValue(obj,['state','status','leader_state']).toLowerCase();
  const offsetRaw=firstValue(obj,['offset_ms','time_offset_ms','skew_ms','clock_skew_ms']);
  const timeOffsetMs=offsetRaw!==''&&Number.isFinite(Number(offsetRaw))?Number(offsetRaw):null;
  const tsRaw=firstValue(obj,['ts','timestamp','time']);
  let ts=null;
  if(tsRaw!==''){
    if(Number.isFinite(Number(tsRaw))) ts=Number(tsRaw);
    else{
      const parsed=Date.parse(tsRaw);
      if(Number.isFinite(parsed)) ts=parsed;
    }
  }

  return {index,raw,type,sender,target,role,task,seq,term,auth,address,session,route,state,timeOffsetMs,ts,fields:obj};
}

function normalizeEvents(input){
  const supplied=input&&typeof input==='object'&&Array.isArray(input.events)?input.events:[];
  const events=[];
  for(const item of supplied.slice(0,MAX_EVENTS)){
    if(typeof item==='string'){
      const parsed=parseLine(item,events.length);
      if(parsed) events.push(parsed);
    }else if(item&&typeof item==='object'){
      const line=Object.entries(item).map(([k,v])=>`${k}=${typeof v==='string'&&/\s/.test(v)?JSON.stringify(v):v}`).join(' ');
      const parsed=parseLine(line,events.length);
      if(parsed) events.push(parsed);
    }
  }
  if(!events.length){
    for(const line of asText(input).split(/\r?\n/).slice(0,MAX_EVENTS)){
      const parsed=parseLine(line,events.length);
      if(parsed) events.push(parsed);
    }
  }
  return events;
}

function badAuth(value){
  return /^(?:none|false|0|no|off|disabled|missing|unsigned|unauthenticated|unauthorized|bypass)$/i.test(String(value||''));
}

function addFinding(findings,id,severity,title,evidence,why,nextCheck,meta={}){
  findings.push({id,severity,state:'candidate',title,evidence:[...new Set(evidence.filter(Boolean))].slice(0,12),why,nextCheck,...meta});
}

function memberRegistry(events){
  const map=new Map();
  function touch(id){
    if(!id) return null;
    if(!map.has(id)) map.set(id,{id,roles:new Set(),addresses:new Set(),sessions:new Set(),auth:new Set(),events:0,first:null,last:null});
    return map.get(id);
  }
  for(const event of events){
    const member=touch(event.sender);
    if(!member) continue;
    member.events++;
    if(event.role) member.roles.add(event.role);
    if(event.address) member.addresses.add(event.address);
    if(event.session) member.sessions.add(event.session);
    if(event.auth) member.auth.add(event.auth);
    if(event.ts!=null){
      if(member.first==null||event.ts<member.first) member.first=event.ts;
      if(member.last==null||event.ts>member.last) member.last=event.ts;
    }
  }
  return [...map.values()].map((row)=>({id:row.id,roles:[...row.roles],addresses:[...row.addresses],sessions:[...row.sessions],auth:[...row.auth],events:row.events,first:row.first,last:row.last}));
}

function buildTopology(events,members){
  const nodes=members.map((m)=>({id:m.id,kind:m.roles.includes('leader')?'leader':'member',roles:m.roles,eventCount:m.events}));
  const edgeMap=new Map();
  for(const event of events){
    if(!event.sender||!event.target) continue;
    const target=/^(?:\*|all|broadcast|multicast)$/i.test(event.target)?'BROADCAST':event.target;
    const key=`${event.sender}->${target}`;
    if(!edgeMap.has(key)) edgeMap.set(key,{from:event.sender,to:target,count:0,types:new Set(),tasks:new Set()});
    const edge=edgeMap.get(key); edge.count++; edge.types.add(event.type); if(event.task) edge.tasks.add(event.task);
  }
  if([...edgeMap.values()].some((edge)=>edge.to==='BROADCAST')) nodes.push({id:'BROADCAST',kind:'broadcast',roles:[],eventCount:0});
  return {nodes,edges:[...edgeMap.values()].map((edge)=>({...edge,types:[...edge.types],tasks:[...edge.tasks]}))};
}

function analyzeSwarmCoordination(input,options={}){
  const events=normalizeEvents(input);
  const members=memberRegistry(events);
  const findings=[];
  const skewLimit=Number.isFinite(Number(options.timeSkewMs))?Math.abs(Number(options.timeSkewMs)):DEFAULT_TIME_SKEW_MS;
  const memberById=new Map(members.map((m)=>[m.id,m]));

  for(const event of events){
    const explicitAdmission=/accepted[_ -]?(?:unknown|unauth)|未知成员.*(?:接受|加入)|未认证.*(?:加入|接入)/i.test(event.raw);
    if(event.type==='JOIN'&&(badAuth(event.auth)||explicitAdmission)){
      addFinding(findings,'swarm-unauthenticated-admission','high','成员准入缺少可验证身份', [event.raw], 'JOIN/准入事件明确出现未认证、unsigned 或接受未知成员的证据。','复测同一节点身份在无有效凭据时是否被拒绝，并记录准入响应。',{member:event.sender||null});
    }
    if(event.type==='TASK_ASSIGN'&&event.sender){
      const roles=new Set([event.role,...(memberById.get(event.sender)?.roles||[])].filter(Boolean));
      if(roles.has('follower')||roles.has('worker')){
        addFinding(findings,'swarm-follower-control','high','Follower/普通成员发出任务分配', [event.raw], '任务分配来自已标记为 follower/worker 的节点，形成角色权限边界候选。','确认接收端是否校验 Leader/调度角色；用同一任务向量做授权负例。',{member:event.sender,task:event.task||null});
      }
      if(/^(?:\*|all|broadcast|multicast)$/i.test(event.target)&&badAuth(event.auth)){
        addFinding(findings,'swarm-unsigned-broadcast-control','high','未认证广播任务控制', [event.raw], 'TASK_ASSIGN 同时满足广播目标与显式未认证/unsigned 条件。','验证成员是否会接受该广播任务；修复后应拒绝同一未签名向量。',{member:event.sender,task:event.task||null});
      }
    }
    if(event.timeOffsetMs!=null&&Math.abs(event.timeOffsetMs)>skewLimit){
      addFinding(findings,'swarm-time-skew','medium','蜂群时钟偏移超过阈值', [event.raw], `观测到 |clock skew|=${Math.abs(event.timeOffsetMs)}ms，超过 ${skewLimit}ms 准备阈值。`,'结合协议允许误差、GPS/PPS/NTP/PTP 来源和任务时序复核是否可造成状态/重放窗口异常。',{member:event.sender||null,offsetMs:event.timeOffsetMs,thresholdMs:skewLimit});
    }
  }

  const leadersByTerm=new Map();
  for(const event of events){
    const leaderSignal=event.type==='LEADER'||event.role==='leader'||event.state==='leader'||event.state==='active-leader';
    if(!leaderSignal||!event.sender) continue;
    const term=event.term||'unspecified';
    if(!leadersByTerm.has(term)) leadersByTerm.set(term,new Map());
    leadersByTerm.get(term).set(event.sender,event.raw);
  }
  for(const [term,leaders] of leadersByTerm){
    if(leaders.size>1){
      addFinding(findings,'swarm-multiple-leaders','high','同一任期出现多个 Leader', [...leaders.values()], `term/epoch=${term} 下同时出现 ${[...leaders.keys()].join('、')} 的 Leader 证据。`,'检查选主仲裁、term 单调性与成员对 Leader 身份的接受规则。',{term,leaders:[...leaders.keys()]});
    }
  }

  const seqGroups=new Map();
  for(const event of events){
    if(!event.sender||event.seq==null) continue;
    const key=`${event.sender}|${event.type}`;
    if(!seqGroups.has(key)) seqGroups.set(key,[]);
    seqGroups.get(key).push(event);
  }
  for(const [key,rows] of seqGroups){
    let previous=null;
    const seen=new Map();
    for(const event of rows.sort((a,b)=>a.index-b.index)){
      if(previous&&event.seq<previous.seq){
        addFinding(findings,'swarm-sequence-rollback','medium','协同消息序列号回退',[previous.raw,event.raw],`${key} 的 sequence 从 ${previous.seq} 回退到 ${event.seq}。`,'确认协议是否允许回绕；若不允许，验证接收端是否拒绝旧序列/重放消息。',{sender:event.sender,type:event.type});
      }
      const seenKey=`${event.seq}|${event.task||''}|${event.route||''}`;
      if(seen.has(seenKey)){
        addFinding(findings,'swarm-replay-candidate','medium','协同消息出现重复序列/任务向量',[seen.get(seenKey).raw,event.raw],`${key} 重复出现 seq=${event.seq}${event.task?` task=${event.task}`:''}。`,'结合时间戳、nonce/签名与接收端状态确认是否是真正重放，而不是合法重传。',{sender:event.sender,seq:event.seq,task:event.task||null});
      }else seen.set(seenKey,event);
      previous=event;
    }
  }

  const taskGroups=new Map();
  for(const event of events){
    if(event.type!=='TASK_ASSIGN'||!event.task) continue;
    if(!taskGroups.has(event.task)) taskGroups.set(event.task,[]);
    taskGroups.get(event.task).push(event);
  }
  const tasks=[];
  for(const [task,rows] of taskGroups){
    const senders=[...new Set(rows.map((r)=>r.sender).filter(Boolean))];
    const targets=[...new Set(rows.map((r)=>r.target).filter(Boolean))];
    const routes=[...new Set(rows.map((r)=>r.route).filter(Boolean))];
    tasks.push({id:task,senders,targets,routes,assignments:rows.map((r)=>({sender:r.sender,target:r.target,route:r.route,seq:r.seq,raw:r.raw}))});
    if(senders.length>1&&(targets.length>1||routes.length>1)){
      addFinding(findings,'swarm-task-conflict','high','同一任务出现多源冲突分配',rows.map((r)=>r.raw),`task=${task} 同时由 ${senders.join('、')} 发出，且目标/航线不一致。`,'核对 Leader 归属、任务版本与最终执行结果；修复后旧/非 Leader 任务应被拒绝。',{task,senders,targets,routes});
    }
  }

  for(const member of members){
    if(member.addresses.length>1&&member.sessions.length>1){
      const evidence=events.filter((e)=>e.sender===member.id&&e.address&&e.session).slice(0,8).map((e)=>e.raw);
      addFinding(findings,'swarm-identity-binding-candidate','medium','同一成员身份绑定到多个地址/会话',evidence,`${member.id} 同时出现 ${member.addresses.length} 个地址和 ${member.sessions.length} 个会话/密钥标识。`,'区分正常漫游/重连与身份复用；验证成员 ID 是否与长期密钥/证书强绑定。',{member:member.id,addresses:member.addresses,sessions:member.sessions});
    }
  }

  const dedup=[]; const seenFinding=new Set();
  for(const finding of findings){
    const key=[finding.id,finding.member||'',finding.task||'',finding.term||'',finding.sender||'',finding.seq??''].join('|');
    if(seenFinding.has(key)) continue; seenFinding.add(key); dedup.push(finding);
  }
  dedup.sort((a,b)=>({high:3,medium:2,low:1}[b.severity]||0)-({high:3,medium:2,low:1}[a.severity]||0));

  const topology=buildTopology(events,members);
  const leaders=[...new Set(events.filter((e)=>e.type==='LEADER'||e.role==='leader'||e.state==='leader'||e.state==='active-leader').map((e)=>e.sender).filter(Boolean))];
  return {
    schema:'newcyber.lowalt-swarm.v1',
    mode:'deterministic-swarm-coordination',
    summary:{events:events.length,members:members.length,leaders:leaders.length,tasks:tasks.length,candidates:dedup.length},
    members,leaders,tasks,topology,findings:dedup,
    eventTape:events.slice(0,300).map((e)=>({index:e.index,type:e.type,sender:e.sender,target:e.target,role:e.role,task:e.task,seq:e.seq,term:e.term,auth:e.auth,timeOffsetMs:e.timeOffsetMs,raw:e.raw})),
    checks:[
      {id:'membership',title:'成员准入 / 身份绑定',status:members.length?'observed':'no-evidence'},
      {id:'leader',title:'Leader / 角色边界',status:leaders.length?'observed':'no-evidence'},
      {id:'task',title:'任务分配完整性',status:tasks.length?'observed':'no-evidence'},
      {id:'freshness',title:'序列 / 重放 / 时间',status:events.some((e)=>e.seq!=null||e.timeOffsetMs!=null)?'observed':'no-evidence'}
    ],
    notes:[
      '所有自动异常均为 candidate；成员地址变化、重传、Leader 切换等都可能有合法原因。',
      '只有在角色、身份、序列、任务或时间证据形成可复核冲突时才生成异常候选。',
      '比赛闭环仍需补充接收端实际接受/拒绝结果、业务/飞行影响、整改和复测。'
    ]
  };
}

module.exports={parseLine,normalizeEvents,analyzeSwarmCoordination};
