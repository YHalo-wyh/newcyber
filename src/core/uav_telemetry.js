const { parseMavlinkFrames } = require('./low_altitude');

function i16(buf, off) { return off + 2 <= buf.length ? buf.readInt16LE(off) : null; }
function u16(buf, off) { return off + 2 <= buf.length ? buf.readUInt16LE(off) : null; }
function i32(buf, off) { return off + 4 <= buf.length ? buf.readInt32LE(off) : null; }
function u32(buf, off) { return off + 4 <= buf.length ? buf.readUInt32LE(off) : null; }
function f32(buf, off) { return off + 4 <= buf.length ? buf.readFloatLE(off) : null; }
function finite(value) { return Number.isFinite(value); }

function decodeTelemetryFrame(frame, index) {
  const p = frame.payload;
  const base = { frameIndex:index + 1, msgid:frame.msgid, sysid:frame.sysid, compid:frame.compid, seq:frame.seq };
  if (frame.msgid === 24 && p.length >= 30) return { ...base, type:'GPS_RAW_INT', lat:i32(p,8) / 1e7, lon:i32(p,12) / 1e7, altM:i32(p,16) / 1000, eph:u16(p,20), epv:u16(p,22), velMs:u16(p,24) / 100, cogDeg:u16(p,26) / 100, fixType:p[28], satellites:p[29] };
  if (frame.msgid === 30 && p.length >= 28) return { ...base, type:'ATTITUDE', timeMs:u32(p,0), roll:f32(p,4), pitch:f32(p,8), yaw:f32(p,12), rollSpeed:f32(p,16), pitchSpeed:f32(p,20), yawSpeed:f32(p,24) };
  if (frame.msgid === 33 && p.length >= 28) return { ...base, type:'GLOBAL_POSITION_INT', timeMs:u32(p,0), lat:i32(p,4) / 1e7, lon:i32(p,8) / 1e7, altM:i32(p,12) / 1000, relativeAltM:i32(p,16) / 1000, vxMs:i16(p,20) / 100, vyMs:i16(p,22) / 100, vzMs:i16(p,24) / 100, headingDeg:u16(p,26) === 65535 ? null : u16(p,26) / 100 };
  if (frame.msgid === 1 && p.length >= 19) return { ...base, type:'SYS_STATUS', sensorsPresent:u32(p,0), sensorsEnabled:u32(p,4), sensorsHealth:u32(p,8), loadPct:u16(p,12) / 10, voltageV:u16(p,14) / 1000, currentA:i16(p,16) === -1 ? null : i16(p,16) / 100, batteryRemaining:p.readInt8(18) };
  if (frame.msgid === 74 && p.length >= 20) return { ...base, type:'VFR_HUD', airspeedMs:f32(p,0), groundspeedMs:f32(p,4), headingDeg:i16(p,8), throttlePct:u16(p,10), altM:f32(p,12), climbMs:f32(p,16) };
  return null;
}

function haversineM(a, b) {
  const R = 6371000;
  const rad = (x) => x * Math.PI / 180;
  const dLat = rad(b.lat - a.lat), dLon = rad(b.lon - a.lon);
  const x = Math.sin(dLat/2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLon/2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(x)));
}

function streamKey(item) { return `${item.sysid}:${item.compid}:${item.type}`; }

function analyzeTelemetryConsistency(input) {
  const frames = parseMavlinkFrames(input);
  const decoded = frames.map(decodeTelemetryFrame).filter(Boolean);
  const anomalies = [];
  const byStream = new Map();
  for (const item of decoded) {
    const key = streamKey(item);
    if (!byStream.has(key)) byStream.set(key, []);
    byStream.get(key).push(item);
  }

  for (const [key, rows] of byStream) {
    if (rows[0]?.type === 'GLOBAL_POSITION_INT') {
      for (let i = 1; i < rows.length; i += 1) {
        const a = rows[i-1], b = rows[i];
        if (!finite(a.lat) || !finite(a.lon) || !finite(b.lat) || !finite(b.lon)) continue;
        const distanceM = haversineM(a,b);
        const dt = a.timeMs != null && b.timeMs != null && b.timeMs > a.timeMs ? (b.timeMs-a.timeMs)/1000 : null;
        const impliedSpeed = dt ? distanceM/dt : null;
        const reported = Math.hypot(b.vxMs || 0,b.vyMs || 0);
        if (impliedSpeed != null && impliedSpeed > Math.max(80, reported * 4 + 20)) anomalies.push({ id:'gps-position-jump', severity:'high', stream:key, frameIndex:b.frameIndex, evidence:`distance=${distanceM.toFixed(1)}m dt=${dt.toFixed(2)}s implied=${impliedSpeed.toFixed(1)}m/s reported=${reported.toFixed(1)}m/s`, meaning:'位置跳变与速度矛盾，验证 GPS spoof/offset 或错误数据源。' });
      }
    }
    if (rows[0]?.type === 'ATTITUDE') {
      for (let i = 1; i < rows.length; i += 1) {
        const a=rows[i-1], b=rows[i];
        const dt = b.timeMs > a.timeMs ? (b.timeMs-a.timeMs)/1000 : null;
        if (!dt) continue;
        const delta = Math.max(Math.abs(b.roll-a.roll),Math.abs(b.pitch-a.pitch),Math.abs(b.yaw-a.yaw));
        const measuredRate = Math.max(Math.abs(b.rollSpeed || 0),Math.abs(b.pitchSpeed || 0),Math.abs(b.yawSpeed || 0));
        const impliedRate = delta/dt;
        if (impliedRate > Math.max(8, measuredRate * 4 + 2)) anomalies.push({ id:'attitude-jump', severity:'medium', stream:key, frameIndex:b.frameIndex, evidence:`angular delta=${delta.toFixed(3)}rad dt=${dt.toFixed(3)}s implied=${impliedRate.toFixed(2)}rad/s gyro=${measuredRate.toFixed(2)}rad/s`, meaning:'姿态跳变与角速度不一致，检查姿态注入/欺骗或时间戳异常。' });
      }
    }
    if (rows[0]?.type === 'SYS_STATUS') {
      for (const item of rows) {
        if (item.batteryRemaining > 100 || item.batteryRemaining < -1) anomalies.push({ id:'battery-range-invalid', severity:'medium', stream:key, frameIndex:item.frameIndex, evidence:`battery_remaining=${item.batteryRemaining}`, meaning:'电池剩余百分比超出协议合理范围。' });
        if (item.voltageV > 100 || (item.voltageV > 0 && item.voltageV < 2)) anomalies.push({ id:'battery-voltage-outlier', severity:'medium', stream:key, frameIndex:item.frameIndex, evidence:`voltage=${item.voltageV}V`, meaning:'电池电压异常，结合机型和 BATTERY_STATUS 复核。' });
        const unhealthy = (item.sensorsEnabled & ~item.sensorsHealth) >>> 0;
        if (unhealthy) anomalies.push({ id:'sensor-health-mismatch', severity:'medium', stream:key, frameIndex:item.frameIndex, evidence:`enabled-but-unhealthy=0x${unhealthy.toString(16)}`, meaning:'启用传感器健康位缺失，关联 STATUSTEXT/飞行模式确认是否真实故障或状态欺骗。' });
      }
    }
  }

  const globals = decoded.filter((x)=>x.type==='GLOBAL_POSITION_INT');
  const gps = decoded.filter((x)=>x.type==='GPS_RAW_INT');
  for (const g of globals) {
    const candidates = gps.filter((x)=>x.sysid===g.sysid && x.compid===g.compid);
    const near = candidates.length ? candidates.reduce((best,x)=>Math.abs((x.frameIndex||0)-g.frameIndex)<Math.abs((best.frameIndex||0)-g.frameIndex)?x:best,candidates[0]) : null;
    if (!near) continue;
    const distance = haversineM(g,near);
    if (distance > 1000) anomalies.push({ id:'gps-source-disagreement', severity:'high', stream:`${g.sysid}:${g.compid}`, frameIndex:g.frameIndex, evidence:`GPS_RAW_INT vs GLOBAL_POSITION_INT=${distance.toFixed(1)}m`, meaning:'同一飞控的两个位置消息严重不一致，优先验证 GPS 注入/欺骗、不同估计器或时间错位。' });
  }

  const vfr = decoded.filter((x)=>x.type==='VFR_HUD');
  for (const item of vfr) {
    const positions = globals.filter((x)=>x.sysid===item.sysid && x.compid===item.compid);
    if (!positions.length) continue;
    const near = positions.reduce((best,x)=>Math.abs(x.frameIndex-item.frameIndex)<Math.abs(best.frameIndex-item.frameIndex)?x:best,positions[0]);
    const reportedGround = Math.hypot(near.vxMs || 0, near.vyMs || 0);
    if (Math.abs(item.groundspeedMs-reportedGround) > Math.max(15,reportedGround*1.5)) anomalies.push({ id:'vfr-groundspeed-disagreement', severity:'medium', stream:`${item.sysid}:${item.compid}`, frameIndex:item.frameIndex, evidence:`VFR=${item.groundspeedMs.toFixed(1)}m/s GLOBAL=${reportedGround.toFixed(1)}m/s`, meaning:'VFR_HUD 地速与位置速度矛盾，复核数据源/欺骗。' });
    if (Math.abs(item.altM-near.relativeAltM) > 500 && Math.abs(item.altM-near.altM) > 500) anomalies.push({ id:'vfr-altitude-disagreement', severity:'medium', stream:`${item.sysid}:${item.compid}`, frameIndex:item.frameIndex, evidence:`VFR alt=${item.altM.toFixed(1)}m GLOBAL alt=${near.altM.toFixed(1)} rel=${near.relativeAltM.toFixed(1)}`, meaning:'VFR_HUD 高度与 GLOBAL_POSITION_INT 均不一致。' });
  }

  const types = {};
  for (const row of decoded) types[row.type]=(types[row.type]||0)+1;
  return {
    parsedFrames:frames.length,
    telemetryFrames:decoded.length,
    messageTypes:types,
    anomalies,
    summary:{ high:anomalies.filter((x)=>x.severity==='high').length, medium:anomalies.filter((x)=>x.severity==='medium').length },
    notes:['物理一致性阈值用于赛题线索排序；机型、时间基准和估计器差异都可能造成合法偏差，需结合完整日志复核。']
  };
}

module.exports = { decodeTelemetryFrame, haversineM, analyzeTelemetryConsistency };
