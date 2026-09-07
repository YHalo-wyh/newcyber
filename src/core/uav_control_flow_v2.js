const base = require('./uav_control_flow');

function nearlyEqual(a,b) {
  if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
  return Math.abs(a-b) <= Math.max(1e-5, Math.abs(a)*1e-4, Math.abs(b)*1e-4);
}

function buildGeofenceTransactions(events) {
  const writes = events.filter((x)=>x.type==='PARAM_SET' && base.familyForParam(x.paramId)==='geofence');
  const values = events.filter((x)=>x.type==='PARAM_VALUE');
  return writes.map((write)=>{
    const confirm = values.find((x)=>x.frameIndex>write.frameIndex && x.frameIndex-write.frameIndex<=80 && String(x.paramId).toUpperCase()===String(write.paramId).toUpperCase()) || null;
    return {
      paramId:write.paramId,
      requestedValue:write.value,
      frameIndex:write.frameIndex,
      writer:`${write.sysid}:${write.compid}`,
      signed:write.signed,
      targetSystem:write.targetSystem,
      targetComponent:write.targetComponent,
      confirmation:confirm ? { frameIndex:confirm.frameIndex, value:confirm.value, source:`${confirm.sysid}:${confirm.compid}` } : null,
      confirmed:confirm ? nearlyEqual(write.value,confirm.value) : null
    };
  });
}

function buildGcsProfiles(events) {
  const controls = events.filter((x)=>['SET_MODE','PARAM_SET','COMMAND_LONG','MISSION_ITEM','MISSION_ITEM_INT','MISSION_COUNT'].includes(x.type));
  const by = new Map();
  for (const event of controls) {
    const key=`${event.sysid}:${event.compid}`;
    const row=by.get(key) || { stream:key, sysid:event.sysid, compid:event.compid, controlEvents:0, signed:0, unsigned:0, targets:{}, types:{} };
    row.controlEvents++;
    event.signed ? row.signed++ : row.unsigned++;
    row.types[event.type]=(row.types[event.type]||0)+1;
    const target=event.targetSystem ?? null;
    if (target!=null) row.targets[target]=(row.targets[target]||0)+1;
    by.set(key,row);
  }
  const profiles=[...by.values()].map((row)=>({ ...row, signedRatio:row.controlEvents ? row.signed/row.controlEvents : 0 }));
  profiles.sort((a,b)=>b.controlEvents-a.controlEvents || a.stream.localeCompare(b.stream));
  return profiles;
}

function analyzeMavlinkControlFlow(input) {
  const result=base.analyzeMavlinkControlFlow(input);
  const geofenceTransactions=buildGeofenceTransactions(result.events || []);
  const gcsProfiles=buildGcsProfiles(result.events || []);
  const findings=[...(result.findings || [])];

  for (const tx of geofenceTransactions) {
    if (tx.confirmed === true) findings.push({ id:'geofence-param-confirmed', severity:'high', frameIndex:tx.confirmation.frameIndex, stream:tx.writer, evidence:`${tx.paramId}=${tx.requestedValue} confirmed by ${tx.confirmation.source}`, meaning:'地理围栏参数写入后收到一致 PARAM_VALUE 回读，状态变更证据较强。' });
    else if (tx.confirmed === false) findings.push({ id:'geofence-param-mismatch', severity:'medium', frameIndex:tx.confirmation.frameIndex, stream:tx.writer, evidence:`${tx.paramId} requested=${tx.requestedValue} readback=${tx.confirmation.value}`, meaning:'围栏写入与回读不一致，不能宣称变更成功。' });
  }

  const primary=gcsProfiles[0] || null;
  for (const challenger of gcsProfiles.slice(1)) {
    const sharedTargets=Object.keys(challenger.targets).filter((t)=>primary && primary.targets[t]);
    if (!sharedTargets.length) continue;
    const downgrade=primary.signedRatio>=0.8 && challenger.unsigned>0 && challenger.signedRatio<0.2;
    findings.push({
      id:downgrade ? 'gcs-signing-downgrade' : 'gcs-competing-controller',
      severity:downgrade ? 'high' : 'medium',
      stream:challenger.stream,
      evidence:`primary=${primary.stream} challenger=${challenger.stream} targets=${sharedTargets.join('/')} signed=${challenger.signed}/${challenger.controlEvents}`,
      meaning:downgrade ? '主控制源高度签名，而竞争控制源基本未签名；优先验证伪 GCS 或签名降级注入。' : '多个控制源对同一飞控发送控制操作；需结合签名、时序和 ACK 判断是否为伪 GCS。'
    });
  }

  const bySysid=new Map();
  for (const profile of gcsProfiles) {
    const set=bySysid.get(profile.sysid) || new Set();
    set.add(profile.compid);
    bySysid.set(profile.sysid,set);
  }
  for (const [sysid,compids] of bySysid) {
    if (compids.size>1) findings.push({ id:'gcs-identity-collision', severity:'medium', evidence:`sysid=${sysid} compids=${[...compids].join(',')}`, meaning:'同一 SYSID 下出现多个控制组件；可能是合法多组件，也可能是身份冲突/伪装，需结合签名和命令目标复核。' });
  }

  return { ...result, geofenceTransactions, gcsProfiles, findings };
}

module.exports={ ...base, nearlyEqual, buildGeofenceTransactions, buildGcsProfiles, analyzeMavlinkControlFlow };
