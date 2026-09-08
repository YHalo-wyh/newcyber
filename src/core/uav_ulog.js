const ULOG_MAGIC = Buffer.from([0x55,0x4c,0x6f,0x67,0x01,0x12,0x35]);
const MAX_MESSAGES = 2000000;
const MAX_SAMPLES_PER_TOPIC = 3000;

const BASIC = Object.freeze({
  int8_t:{size:1,read:(b,o)=>b.readInt8(o)}, uint8_t:{size:1,read:(b,o)=>b.readUInt8(o)},
  int16_t:{size:2,read:(b,o)=>b.readInt16LE(o)}, uint16_t:{size:2,read:(b,o)=>b.readUInt16LE(o)},
  int32_t:{size:4,read:(b,o)=>b.readInt32LE(o)}, uint32_t:{size:4,read:(b,o)=>b.readUInt32LE(o)},
  int64_t:{size:8,read:(b,o)=>Number(b.readBigInt64LE(o))}, uint64_t:{size:8,read:(b,o)=>Number(b.readBigUInt64LE(o))},
  float:{size:4,read:(b,o)=>b.readFloatLE(o)}, double:{size:8,read:(b,o)=>b.readDoubleLE(o)},
  bool:{size:1,read:(b,o)=>Boolean(b.readUInt8(o))}, char:{size:1,read:(b,o)=>b.readUInt8(o)}
});

function parseType(type) {
  const m=String(type||'').match(/^([A-Za-z0-9_\-/]+)(?:\[(\d+)\])?$/);
  return m ? { base:m[1], count:m[2]?Number(m[2]):1 } : null;
}

function parseFormatString(text) {
  const colon=text.indexOf(':'); if (colon<=0) return null;
  const name=text.slice(0,colon).trim(); if (!name) return null;
  const fields=[];
  for (const raw of text.slice(colon+1).split(';')) {
    const part=raw.trim(); if (!part) continue;
    const m=part.match(/^([^\s]+)\s+([A-Za-z0-9_]+)$/); if (!m) continue;
    const t=parseType(m[1]); if (!t || !Number.isFinite(t.count) || t.count<1 || t.count>100000) continue;
    fields.push({ type:t.base, count:t.count, name:m[2] });
  }
  return fields.length ? { name, fields, raw:text } : null;
}

function expandFormat(name, formats, prefix='', stack=new Set(), depth=0) {
  if (depth>12 || stack.has(name)) return null;
  const fmt=formats.get(name); if (!fmt) return null;
  const next=new Set(stack); next.add(name);
  const out=[]; let offset=0;
  for (const field of fmt.fields) {
    if (BASIC[field.type]) {
      const spec=BASIC[field.type];
      if (field.count===1) out.push({ name:`${prefix}${field.name}`, type:field.type, offset, size:spec.size });
      else if (field.type==='char') out.push({ name:`${prefix}${field.name}`, type:'char[]', offset, size:field.count, count:field.count });
      else for (let i=0;i<field.count;i+=1) out.push({ name:`${prefix}${field.name}[${i}]`, type:field.type, offset:offset+i*spec.size, size:spec.size });
      offset += spec.size*field.count;
      continue;
    }
    const nested=expandFormat(field.type,formats,'',next,depth+1); if (!nested) return null;
    const nestedSize=nested.reduce((max,f)=>Math.max(max,f.offset+f.size),0);
    for (let i=0;i<field.count;i+=1) {
      const childPrefix=`${prefix}${field.name}${field.count>1?`[${i}]`:''}.`;
      for (const child of nested) out.push({ ...child,name:`${childPrefix}${child.name}`,offset:offset+i*nestedSize+child.offset });
    }
    offset += nestedSize*field.count;
  }
  return out;
}

function decodeFields(payload, fields) {
  const out={};
  for (const field of fields) {
    if (field.offset+field.size>payload.length) continue;
    if (field.name.split('.').pop().startsWith('_padding')) continue;
    try {
      if (field.type==='char[]') {
        const raw=payload.subarray(field.offset,field.offset+field.size); const zero=raw.indexOf(0); out[field.name]=raw.subarray(0,zero>=0?zero:raw.length).toString('utf8');
      } else out[field.name]=BASIC[field.type].read(payload,field.offset);
    } catch {}
  }
  return out;
}

function parseTypedValue(payload, offset=0) {
  if (offset>=payload.length) return null;
  const keyLen=payload[offset]; const keyStart=offset+1; const keyEnd=keyStart+keyLen;
  if (keyEnd>payload.length) return null;
  const key=payload.subarray(keyStart,keyEnd).toString('utf8'); const split=key.indexOf(' '); if (split<=0) return null;
  const typeRaw=key.slice(0,split); const name=key.slice(split+1); const t=parseType(typeRaw); if (!t) return { type:typeRaw,name,value:payload.subarray(keyEnd).toString('hex') };
  if (t.type==='char' || t.base==='char') return { type:typeRaw,name,value:payload.subarray(keyEnd,keyEnd+t.count).toString('utf8').replace(/\0.*$/s,'') };
  const spec=BASIC[t.base]; if (!spec) return { type:typeRaw,name,value:payload.subarray(keyEnd).toString('hex') };
  if (t.count===1 && keyEnd+spec.size<=payload.length) return { type:typeRaw,name,value:spec.read(payload,keyEnd) };
  const values=[]; for (let i=0;i<t.count && keyEnd+(i+1)*spec.size<=payload.length;i+=1) values.push(spec.read(payload,keyEnd+i*spec.size));
  return { type:typeRaw,name,value:values };
}

function timestampSec(row) {
  const value=Number(row?.timestamp ?? row?.timestamp_sample ?? row?.time_utc_usec);
  if (!Number.isFinite(value)) return null;
  return value>1e10 ? value/1e6 : value>1e7 ? value/1e6 : value;
}

function deg(value) {
  const n=Number(value); if (!Number.isFinite(n)) return null;
  return Math.abs(n)>180 ? n/1e7 : n;
}

function haversineM(a,b) {
  const R=6371000; const rad=(x)=>x*Math.PI/180;
  const p1=rad(a.lat),p2=rad(b.lat),dp=rad(b.lat-a.lat),dl=rad(b.lon-a.lon);
  const s=Math.sin(dp/2)**2+Math.cos(p1)*Math.cos(p2)*Math.sin(dl/2)**2;
  return 2*R*Math.atan2(Math.sqrt(s),Math.sqrt(Math.max(0,1-s)));
}

function summarize(parsed) {
  const get=(name)=>parsed.topicSamples[name]||[];
  const gpsSource=get('vehicle_gps_position').length?get('vehicle_gps_position'):get('sensor_gps');
  const gps=gpsSource.map((r)=>({ timestamp:r.timestamp, timeSec:timestampSec(r), lat:deg(r.lat), lon:deg(r.lon), alt:Number(r.alt ?? r.altitude_msl_m ?? r.alt_ellipsoid)||null, vel_m_s:Number(r.vel_m_s ?? r.vel_n_m_s)||null, fix_type:r.fix_type ?? null, satellites_used:r.satellites_used ?? r.satellites ?? null, raw:r })).filter((x)=>x.lat!=null&&x.lon!=null).slice(0,3000);
  const attitude=get('vehicle_attitude').map((r)=>({ timestamp:r.timestamp,timeSec:timestampSec(r),q:[r['q[0]'],r['q[1]'],r['q[2]'],r['q[3]']].filter((x)=>x!==undefined),raw:r })).slice(0,3000);
  const statuses=get('vehicle_status'); const modes=[]; let prev=null;
  for (const row of statuses) {
    const state={ timestamp:row.timestamp,timeSec:timestampSec(row),nav_state:row.nav_state,arming_state:row.arming_state,vehicle_type:row.vehicle_type,failsafe:row.failsafe };
    const key=JSON.stringify([state.nav_state,state.arming_state,state.failsafe]); if (key!==prev) { modes.push(state); prev=key; }
  }
  const battery=get('battery_status').slice(0,2000);
  const estimator=get('estimator_status').slice(0,2000);
  const findings=[];
  if (parsed.dropouts.length) findings.push({ id:'ulog-dropout',severity:'medium',evidence:`dropouts=${parsed.dropouts.length}, maxMs=${Math.max(...parsed.dropouts.map((x)=>x.durationMs))}`,meaning:'ULog 记录了日志 dropout；异常时间窗内的数据缺口需要与控制/遥测结论区分。' });
  if (modes.length>1) findings.push({ id:'ulog-vehicle-status-transition',severity:'info',evidence:`stateTransitions=${modes.length}`,meaning:'已恢复 vehicle_status 状态转折，可与 MAVLink 控制命令和安全事件按时间对齐。' });
  if (gps.length>1) {
    let worst=null;
    for (let i=1;i<gps.length;i+=1) {
      const dt=(gps[i].timeSec??0)-(gps[i-1].timeSec??0); if (!(dt>0&&dt<120)) continue;
      const distance=haversineM(gps[i-1],gps[i]); const speed=distance/dt;
      if (!worst||speed>worst.speedMps) worst={ from:i-1,to:i,dt,distance,speedMps:speed };
    }
    if (worst&&worst.speedMps>150) findings.push({ id:'ulog-gps-position-jump',severity:'medium',evidence:`impliedSpeed=${worst.speedMps.toFixed(2)}m/s distance=${worst.distance.toFixed(1)}m dt=${worst.dt.toFixed(3)}s`,meaning:'ULog GPS 相邻位置隐含速度异常高；结合 fix_type、estimator 与其他位置源判断 GPS 欺骗/跳变或日志异常。' });
  }
  if (battery.some((r)=>Number.isFinite(Number(r.remaining))&&(Number(r.remaining)<-0.05||Number(r.remaining)>1.05))) findings.push({ id:'ulog-battery-range',severity:'low',evidence:'battery_status.remaining outside expected normalized range',meaning:'电池剩余量字段出现异常范围，需确认 PX4 版本字段语义后再判断遥测欺骗或传感器异常。' });
  if (gps.length) findings.push({ id:'ulog-gps-track',severity:'info',evidence:`gpsRows=${gps.length}`,meaning:'已从 ULog topic 定义恢复 GPS 轨迹，可与 MAVLink/NMEA 交叉校验。' });
  if (attitude.length) findings.push({ id:'ulog-attitude-track',severity:'info',evidence:`attitudeRows=${attitude.length}`,meaning:'已从 vehicle_attitude 恢复四元数时间线，可与外部 ATTITUDE/IMU 数据做一致性对照。' });
  return { gps,attitude,modes,battery,estimator,findings };
}

function parseUlog(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length<16 || !buffer.subarray(0,7).equals(ULOG_MAGIC)) return null;
  const version=buffer[7]; const startTimestamp=Number(buffer.readBigUInt64LE(8));
  const formats=new Map(); const subscriptions=new Map(); const messageCounts={}; const topicSamples={}; const parameters=[]; const info={}; const logging=[]; const dropouts=[]; const errors=[];
  let offset=16; let count=0; let truncated=false;
  while (offset+3<=buffer.length && count<MAX_MESSAGES) {
    const size=buffer.readUInt16LE(offset); const type=String.fromCharCode(buffer[offset+2]); const start=offset+3; const end=start+size;
    if (end>buffer.length) { truncated=true; break; }
    const payload=buffer.subarray(start,end); count+=1; messageCounts[type]=(messageCounts[type]||0)+1;
    try {
      if (type==='F') { const fmt=parseFormatString(payload.toString('utf8')); if (fmt) formats.set(fmt.name,fmt); }
      else if (type==='A' && payload.length>=3) { const multiId=payload[0]; const msgId=payload.readUInt16LE(1); const name=payload.subarray(3).toString('utf8').replace(/\0.*$/s,''); subscriptions.set(msgId,{msgId,multiId,name,fields:null}); }
      else if (type==='R' && payload.length>=2) subscriptions.delete(payload.readUInt16LE(0));
      else if (type==='D' && payload.length>=2) {
        const msgId=payload.readUInt16LE(0); const sub=subscriptions.get(msgId); if (sub) {
          if (!sub.fields) sub.fields=expandFormat(sub.name,formats);
          if (sub.fields) {
            const row=decodeFields(payload.subarray(2),sub.fields); const name=sub.multiId?`${sub.name}:${sub.multiId}`:sub.name;
            messageCounts[name]=(messageCounts[name]||0)+1;
            if (!topicSamples[sub.name]) topicSamples[sub.name]=[];
            if (topicSamples[sub.name].length<MAX_SAMPLES_PER_TOPIC) topicSamples[sub.name].push(row);
          }
        }
      } else if (type==='P') { const item=parseTypedValue(payload); if (item) parameters.push(item); }
      else if (type==='Q' && payload.length>=2) { const item=parseTypedValue(payload,1); if (item) parameters.push({ ...item,defaultTypes:payload[0] }); }
      else if (type==='I') { const item=parseTypedValue(payload); if (item) info[item.name]=item.value; }
      else if (type==='M' && payload.length>=2) { const item=parseTypedValue(payload,1); if (item) info[item.name]=item.value; }
      else if (type==='O' && payload.length>=2) dropouts.push({ durationMs:payload.readUInt16LE(0),messageIndex:count });
      else if (type==='L' && payload.length>=9) logging.push({ level:String.fromCharCode(payload[0]),timestamp:Number(payload.readBigUInt64LE(1)),message:payload.subarray(9).toString('utf8').replace(/\0.*$/s,'') });
      else if (type==='C' && payload.length>=11) logging.push({ level:String.fromCharCode(payload[0]),tag:payload.readUInt16LE(1),timestamp:Number(payload.readBigUInt64LE(3)),message:payload.subarray(11).toString('utf8').replace(/\0.*$/s,'') });
    } catch (error) { if (errors.length<100) errors.push({ messageIndex:count,type,error:error.message }); }
    offset=end;
  }
  if (count>=MAX_MESSAGES&&offset<buffer.length) truncated=true;
  const summary=summarize({topicSamples,dropouts});
  const times=[];
  for (const samples of Object.values(topicSamples)) for (const row of samples) { const t=timestampSec(row); if (t!=null) times.push(t); }
  const timeRange=times.length?{startSec:Math.min(...times),endSec:Math.max(...times),durationSec:Math.max(...times)-Math.min(...times)}:null;
  const events=[...logging.slice(0,2000),...dropouts.slice(0,500).map((x)=>({type:'dropout',...x}))];
  return {
    format:'px4-ulog',size:buffer.length,version,startTimestamp,messageCount:count,messageCounts,formatCount:formats.size,subscriptionCount:subscriptions.size,
    topics:Object.entries(topicSamples).map(([name,samples])=>({name,samples:samples.length,fields:Object.keys(samples[0]||{}).slice(0,80)})).sort((a,b)=>b.samples-a.samples),
    timeRange,params:parameters.slice(0,3000),gps:summary.gps,attitude:summary.attitude,modes:summary.modes,events,battery:summary.battery,estimator:summary.estimator,
    info,dropouts,parseErrors:errors,findings:summary.findings,truncated,
    notes:['ULog 数据字段来自文件自身 F(format) 定义，并通过 A(subscription) 的 msg_id 关联 D(data)，不按固定 PX4 版本猜字段偏移。','嵌套 format 仅在定义可完整解析时展开；未知/损坏消息保留计数并停止对该 topic 猜测。']
  };
}

module.exports={ ULOG_MAGIC, BASIC, parseFormatString, expandFormat, decodeFields, parseUlog };
