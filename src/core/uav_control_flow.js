const { parseMavlinkFrames } = require('./low_altitude');

const COMMANDS = Object.freeze({
  22: 'NAV_TAKEOFF',
  176: 'DO_SET_MODE',
  179: 'DO_SET_HOME',
  185: 'DO_FLIGHTTERMINATION',
  200: 'DO_CONTROL_VIDEO',
  203: 'DO_DIGICAM_CONTROL',
  205: 'DO_MOUNT_CONTROL',
  206: 'DO_SET_CAM_TRIGG_DIST',
  400: 'COMPONENT_ARM_DISARM',
  500: 'START_RX_PAIR',
  1000: 'DO_GIMBAL_MANAGER_PITCHYAW'
});
const ACK_RESULTS = Object.freeze({0:'ACCEPTED',1:'TEMPORARILY_REJECTED',2:'DENIED',3:'UNSUPPORTED',4:'FAILED',5:'IN_PROGRESS',6:'CANCELLED'});

function asciiId(buffer, offset, length) {
  const raw = buffer.subarray(offset, Math.min(buffer.length, offset + length));
  const zero = raw.indexOf(0);
  return raw.subarray(0, zero >= 0 ? zero : raw.length).toString('utf8').trim();
}

function decodeControl(frame, index) {
  const p = frame.payload;
  const common = { frameIndex:index + 1, sysid:frame.sysid, compid:frame.compid, seq:frame.seq, signed:frame.signed, signature:frame.signature || null };
  if (frame.msgid === 11 && p.length >= 6) return { ...common, type:'SET_MODE', customMode:p.readUInt32LE(0), targetSystem:p[4], baseMode:p[5] };
  if (frame.msgid === 23 && p.length >= 23) return { ...common, type:'PARAM_SET', value:p.readFloatLE(0), targetSystem:p[4], targetComponent:p[5], paramId:asciiId(p,6,16), paramType:p[22] };
  if (frame.msgid === 22 && p.length >= 25) return { ...common, type:'PARAM_VALUE', value:p.readFloatLE(0), count:p.readUInt16LE(4), index:p.readUInt16LE(6), paramId:asciiId(p,8,16), paramType:p[24] };
  if (frame.msgid === 44 && p.length >= 4) return { ...common, type:'MISSION_COUNT', count:p.readUInt16LE(0), targetSystem:p[2], targetComponent:p[3], missionType:p.length > 4 ? p[4] : 0 };
  if (frame.msgid === 39 && p.length >= 37) return { ...common, type:'MISSION_ITEM', params:[p.readFloatLE(0),p.readFloatLE(4),p.readFloatLE(8),p.readFloatLE(12)], x:p.readFloatLE(16), y:p.readFloatLE(20), z:p.readFloatLE(24), missionSeq:p.readUInt16LE(28), command:p.readUInt16LE(30), targetSystem:p[32], targetComponent:p[33], frame:p[34], current:p[35], autocontinue:p[36], missionType:p.length > 37 ? p[37] : 0 };
  if (frame.msgid === 73 && p.length >= 37) return { ...common, type:'MISSION_ITEM_INT', params:[p.readFloatLE(0),p.readFloatLE(4),p.readFloatLE(8),p.readFloatLE(12)], x:p.readInt32LE(16) / 1e7, y:p.readInt32LE(20) / 1e7, z:p.readFloatLE(24), missionSeq:p.readUInt16LE(28), command:p.readUInt16LE(30), targetSystem:p[32], targetComponent:p[33], frame:p[34], current:p[35], autocontinue:p[36], missionType:p.length > 37 ? p[37] : 0 };
  if (frame.msgid === 76 && p.length >= 33) return { ...common, type:'COMMAND_LONG', params:Array.from({length:7},(_,i)=>p.readFloatLE(i*4)), command:p.readUInt16LE(28), commandName:COMMANDS[p.readUInt16LE(28)] || `CMD_${p.readUInt16LE(28)}`, targetSystem:p[30], targetComponent:p[31], confirmation:p[32] };
  if (frame.msgid === 77 && p.length >= 3) return { ...common, type:'COMMAND_ACK', command:p.readUInt16LE(0), commandName:COMMANDS[p.readUInt16LE(0)] || `CMD_${p.readUInt16LE(0)}`, result:p[2], resultName:ACK_RESULTS[p[2]] || `RESULT_${p[2]}`, progress:p.length > 3 ? p[3] : null, targetSystem:p.length > 8 ? p[8] : null, targetComponent:p.length > 9 ? p[9] : null };
  return null;
}

function familyForParam(paramId) {
  const id = String(paramId || '').toUpperCase();
  if (/^FENCE_|GEOFENCE/.test(id)) return 'geofence';
  if (/^(?:FS_|FAILSAFE|ARMING_)/.test(id)) return 'failsafe-arming';
  if (/^(?:GPS_|EKF|AHRS|COMPASS_)/.test(id)) return 'navigation-sensor';
  if (/^(?:MAV_|SERIAL|BRD_SER|NET_|WIFI_)/.test(id)) return 'link-security';
  if (/^(?:LOG_|LOGGING)/.test(id)) return 'logging';
  if (/^(?:CAM_|MNT_|GMBL_)/.test(id)) return 'camera-gimbal';
  return 'other';
}

function commandFamily(command) {
  if (command === 185) return 'flight-termination';
  if (command === 179) return 'home-position';
  if (command === 176) return 'flight-mode';
  if (command === 400) return 'arming';
  if ([200,203,205,206,1000].includes(command)) return 'camera-gimbal';
  if (command === 22) return 'takeoff';
  return 'other';
}

function analyzeMavlinkControlFlow(input) {
  const frames = parseMavlinkFrames(input);
  const events = frames.map(decodeControl).filter(Boolean);
  const streams = {};
  for (const event of events) {
    const key = `${event.sysid}:${event.compid}`;
    const item = streams[key] ||= { stream:key, signed:0, unsigned:0, events:0, types:{} };
    event.signed ? item.signed++ : item.unsigned++;
    item.events++;
    item.types[event.type]=(item.types[event.type]||0)+1;
  }

  const paramWrites = events.filter((e)=>e.type==='PARAM_SET').map((e)=>({ ...e, family:familyForParam(e.paramId) }));
  const modeChanges = events.filter((e)=>e.type==='SET_MODE');
  const missionItems = events.filter((e)=>e.type==='MISSION_ITEM' || e.type==='MISSION_ITEM_INT');
  const commands = events.filter((e)=>e.type==='COMMAND_LONG').map((e)=>({ ...e, family:commandFamily(e.command) }));
  const acks = events.filter((e)=>e.type==='COMMAND_ACK');
  const commandChains = commands.map((cmd)=>{
    const ack = acks.find((a)=>a.command===cmd.command && a.frameIndex>cmd.frameIndex && a.frameIndex-cmd.frameIndex<=50) || null;
    return { command:cmd, ack, accepted:ack ? ack.result===0 || ack.result===5 : null };
  });

  const findings = [];
  for (const write of paramWrites) {
    if (write.family === 'geofence') findings.push({ id:'geofence-param-write', severity:'medium', frameIndex:write.frameIndex, stream:`${write.sysid}:${write.compid}`, evidence:`${write.paramId}=${write.value}`, meaning:'围栏参数被写入；检查来源、签名以及写入前后值。' });
    if (write.family === 'failsafe-arming') findings.push({ id:'failsafe-param-write', severity:'medium', frameIndex:write.frameIndex, stream:`${write.sysid}:${write.compid}`, evidence:`${write.paramId}=${write.value}`, meaning:'Failsafe/arming 参数被写入，可能改变起飞或失联安全状态。' });
  }
  for (const chain of commandChains) {
    const cmd = chain.command;
    if (cmd.family === 'flight-termination') findings.push({ id:'flight-termination-command', severity:'high', frameIndex:cmd.frameIndex, stream:`${cmd.sysid}:${cmd.compid}`, evidence:`${cmd.commandName} ack=${chain.ack?.resultName || 'none'}`, meaning:'检测到飞行终止类控制命令；ACK 接受时优先级最高。' });
    if (cmd.family === 'home-position') findings.push({ id:'home-position-command', severity:'medium', frameIndex:cmd.frameIndex, stream:`${cmd.sysid}:${cmd.compid}`, evidence:`${cmd.commandName} params=${cmd.params.join(',')}`, meaning:'检测到返航点设置命令，需恢复坐标/来源与 ACK。' });
    if (cmd.family === 'camera-gimbal') findings.push({ id:'camera-gimbal-command', severity:'medium', frameIndex:cmd.frameIndex, stream:`${cmd.sysid}:${cmd.compid}`, evidence:cmd.commandName, meaning:'相机/云台控制命令出现，检查来源和 target component。' });
  }
  if (missionItems.length) {
    const streamsSet = new Set(missionItems.map((x)=>`${x.sysid}:${x.compid}`));
    findings.push({ id:'mission-upload-observed', severity:'info', frameIndex:missionItems[0].frameIndex, evidence:`items=${missionItems.length} controllers=${[...streamsSet].join(',')}`, meaning:'检测到航点/任务项；按 seq/坐标重建任务并比较发送方。' });
  }
  if (Object.keys(streams).length > 1 && events.some((x)=>['SET_MODE','PARAM_SET','COMMAND_LONG','MISSION_ITEM','MISSION_ITEM_INT'].includes(x.type))) {
    findings.push({ id:'multiple-control-streams', severity:'medium', evidence:Object.keys(streams).join(', '), meaning:'存在多个控制发送方；比较签名、sysid/compid 和命令时间线识别伪 GCS/接管。' });
  }

  return {
    parsedFrames:frames.length,
    controlEvents:events.length,
    streams:Object.values(streams),
    events,
    paramWrites,
    modeChanges,
    mission:{ countEvents:events.filter((x)=>x.type==='MISSION_COUNT'), items:missionItems },
    commands:commandChains,
    findings,
    notes:['控制命令出现不等于未授权；优先使用 ACK、签名、发送方画像和后续 HEARTBEAT/参数回读确认实际影响。']
  };
}

module.exports = { COMMANDS, ACK_RESULTS, decodeControl, familyForParam, commandFamily, analyzeMavlinkControlFlow };
