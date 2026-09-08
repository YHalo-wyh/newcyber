function checksumNmea(sentence) {
  const line=String(sentence||'').trim();
  if (!line.startsWith('$')) return null;
  const star=line.indexOf('*');
  const body=line.slice(1,star>=0?star:line.length);
  let value=0;
  for (const ch of body) value^=ch.charCodeAt(0);
  return value;
}

function verifyChecksum(sentence) {
  const line=String(sentence||'').trim();
  const star=line.indexOf('*');
  if (star<0 || star+3>line.length) return { present:false, valid:null, expected:null, computed:checksumNmea(line) };
  const expected=parseInt(line.slice(star+1,star+3),16);
  const computed=checksumNmea(line);
  return { present:true, valid:Number.isInteger(expected)&&computed===expected, expected, computed };
}

function parseCoord(raw, hemi, isLon=false) {
  const text=String(raw||'').trim();
  if (!/^\d+(?:\.\d+)?$/.test(text)) return null;
  const degDigits=isLon?3:2;
  if (text.length<degDigits+2) return null;
  const deg=Number(text.slice(0,degDigits));
  const min=Number(text.slice(degDigits));
  if (!Number.isFinite(deg)||!Number.isFinite(min)||min>=60) return null;
  let value=deg+min/60;
  if (/^[SW]$/i.test(String(hemi||''))) value=-value;
  return value;
}

function parseTime(raw) {
  const text=String(raw||'').trim();
  const m=text.match(/^(\d{2})(\d{2})(\d{2})(?:\.(\d+))?$/);
  if (!m) return null;
  const h=Number(m[1]), min=Number(m[2]), sec=Number(m[3])+Number(`0.${m[4]||0}`);
  if (h>23||min>59||sec>=60) return null;
  return h*3600+min*60+sec;
}

function haversineMeters(a,b) {
  const rad=(x)=>x*Math.PI/180;
  const R=6371000;
  const dLat=rad(b.lat-a.lat), dLon=rad(b.lon-a.lon);
  const lat1=rad(a.lat), lat2=rad(b.lat);
  const q=Math.sin(dLat/2)**2+Math.cos(lat1)*Math.cos(lat2)*Math.sin(dLon/2)**2;
  return 2*R*Math.asin(Math.min(1,Math.sqrt(q)));
}

function parseNmea(input) {
  const lines=String(input||'').split(/\r?\n/).map((x)=>x.trim()).filter((x)=>x.startsWith('$'));
  const records=[];
  for (let i=0;i<lines.length;i+=1) {
    const line=lines[i];
    const star=line.indexOf('*');
    const body=line.slice(1,star>=0?star:line.length);
    const parts=body.split(',');
    const tag=parts[0].slice(-3).toUpperCase();
    const checksum=verifyChecksum(line);
    const base={ line:i+1, raw:line, talker:parts[0].slice(0,-3), tag, checksum };
    if (tag==='GGA') {
      records.push({ ...base, type:'GGA', timeSec:parseTime(parts[1]), lat:parseCoord(parts[2],parts[3],false), lon:parseCoord(parts[4],parts[5],true), fixQuality:Number(parts[6]), satellites:Number(parts[7]), hdop:Number(parts[8]), altitudeM:Number(parts[9]) });
    } else if (tag==='RMC') {
      records.push({ ...base, type:'RMC', timeSec:parseTime(parts[1]), status:parts[2], lat:parseCoord(parts[3],parts[4],false), lon:parseCoord(parts[5],parts[6],true), speedKnots:Number(parts[7]), courseDeg:Number(parts[8]), date:parts[9]||null });
    } else if (tag==='GSV') {
      const sats=[];
      for (let p=4;p+3<parts.length;p+=4) sats.push({ prn:parts[p], elevation:Number(parts[p+1]), azimuth:Number(parts[p+2]), snr:Number(parts[p+3]) });
      records.push({ ...base, type:'GSV', totalMessages:Number(parts[1]), messageNumber:Number(parts[2]), satellitesInView:Number(parts[3]), sats });
    } else if (tag==='GSA') {
      records.push({ ...base, type:'GSA', mode:parts[1], fixType:Number(parts[2]), pdop:Number(parts[15]), hdop:Number(parts[16]), vdop:Number(parts[17]) });
    } else records.push(base);
  }
  return records;
}

function finite(value) { return Number.isFinite(value); }

function analyzeGnssLog(input, options={}) {
  const records=parseNmea(input);
  const findings=[];
  const points=records.filter((r)=>['GGA','RMC'].includes(r.type)&&finite(r.lat)&&finite(r.lon)&&finite(r.timeSec));
  const checksumFailed=records.filter((r)=>r.checksum.present&&r.checksum.valid===false);
  const checksumMissing=records.filter((r)=>!r.checksum.present);
  if (checksumFailed.length) findings.push({ id:'gnss-nmea-checksum-failed',severity:'high',title:'NMEA checksum 校验失败',evidence:`failed=${checksumFailed.length}/${records.length}`,meaning:'报文可能被截断、损坏或篡改；先排除采集/串口错误再判断攻击。' });
  if (checksumMissing.length && checksumMissing.length===records.length) findings.push({ id:'gnss-nmea-checksum-absent',severity:'info',title:'NMEA 全部缺少 checksum',evidence:`missing=${checksumMissing.length}`,meaning:'部分日志工具会主动去除 checksum；不能单独视为攻击证据。' });

  const maxSpeed=Number(options.maxSpeedMps)||120;
  const jumps=[]; const timeRollbacks=[]; const speedMismatches=[];
  let previous=null;
  for (const point of points) {
    if (previous) {
      let dt=point.timeSec-previous.timeSec;
      if (dt<-43200) dt+=86400;
      if (dt<0) timeRollbacks.push({ fromLine:previous.line,toLine:point.line,previous:previous.timeSec,actual:point.timeSec });
      if (dt>0) {
        const distance=haversineMeters(previous,point);
        const derived=distance/dt;
        if (derived>maxSpeed) jumps.push({ fromLine:previous.line,toLine:point.line,dt,distanceM:distance,speedMps:derived,from:{lat:previous.lat,lon:previous.lon},to:{lat:point.lat,lon:point.lon} });
        const rmc=point.type==='RMC'?point:previous.type==='RMC'?previous:null;
        if (rmc&&finite(rmc.speedKnots)) {
          const reported=rmc.speedKnots*0.514444;
          if (derived>5 && Math.abs(derived-reported)>Math.max(10,reported*0.8)) speedMismatches.push({ line:point.line,derivedMps:derived,reportedMps:reported });
        }
      }
    }
    previous=point;
  }

  if (timeRollbacks.length) findings.push({ id:'gnss-time-rollback',severity:'medium',title:'GNSS 时间出现回退',evidence:timeRollbacks.slice(0,8),meaning:'可能是日志拼接、跨日处理错误或欺骗/重放信号；需与系统时间和飞控时间戳交叉验证。' });
  if (jumps.length) findings.push({ id:'gnss-position-physics-violation',severity:'high',title:'位置跳变超出物理速度阈值',evidence:jumps.slice(0,8),meaning:`相邻定位点隐含速度超过 ${maxSpeed} m/s；优先检查 GPS spoof/offset、数据注入或时间轴异常。` });
  if (speedMismatches.length) findings.push({ id:'gnss-speed-position-mismatch',severity:'medium',title:'RMC 地速与位置变化不一致',evidence:speedMismatches.slice(0,8),meaning:'位置轨迹与接收机报告地速互相矛盾，属于多字段交叉证据。' });

  const gga=records.filter((r)=>r.type==='GGA');
  const satJumps=[]; let prevGga=null;
  for (const row of gga) {
    if (prevGga&&finite(row.satellites)&&finite(prevGga.satellites)&&Math.abs(row.satellites-prevGga.satellites)>=8) satJumps.push({ fromLine:prevGga.line,toLine:row.line,from:prevGga.satellites,to:row.satellites });
    prevGga=row;
  }
  if (satJumps.length) findings.push({ id:'gnss-satellite-count-jump',severity:'medium',title:'可见/参与定位卫星数突变',evidence:satJumps.slice(0,8),meaning:'卫星数突变可由遮挡、接收机重捕获或欺骗造成；需结合 SNR/HDOP/轨迹判断。' });

  const gsv=records.filter((r)=>r.type==='GSV');
  const snrValues=gsv.flatMap((r)=>r.sats||[]).map((s)=>s.snr).filter(finite);
  const identicalSnr=snrValues.length>=12 && new Set(snrValues).size<=2;
  if (identicalSnr) findings.push({ id:'gnss-uniform-snr-candidate',severity:'medium',title:'多卫星 SNR 过度一致',evidence:`samples=${snrValues.length}, unique=${new Set(snrValues).size}`,meaning:'异常一致的 C/N0/SNR 可能是合成/回放环境特征，也可能来自日志量化；需与真实接收机分辨率核对。' });

  const fixLoss=gga.filter((r)=>finite(r.fixQuality)&&r.fixQuality===0).length;
  const hdopBad=gga.filter((r)=>finite(r.hdop)&&r.hdop>10).length;
  if (fixLoss||hdopBad) findings.push({ id:'gnss-jamming-quality-degradation',severity:'info',title:'定位质量下降/干扰候选',evidence:`noFix=${fixLoss}, hdop>10=${hdopBad}`,meaning:'无 fix 与高 HDOP 更像干扰/遮挡/弱信号证据，不能仅凭这一项区分恶意干扰与环境问题。' });

  const nextActions=[];
  if (jumps.length||speedMismatches.length) nextActions.push('把 NMEA 与 MAVLink GPS_RAW_INT / GLOBAL_POSITION_INT / ULog GPS 同时间轴对齐，判断异常来自接收机层还是飞控消息层。');
  if (gsv.length) nextActions.push('继续按 PRN 聚合 elevation/azimuth/SNR，检查卫星集合、SNR 与轨迹变化是否同步异常。');
  if (!gsv.length) nextActions.push('若题目提供原始 GNSS/SDR 记录，补充 GSV/CN0/多普勒或 IQ 频谱证据；仅 GGA/RMC 无法证明 RF 层欺骗。');

  return {
    records:records.length,
    gga:gga.length,
    rmc:records.filter((r)=>r.type==='RMC').length,
    gsv:gsv.length,
    checksumFailed:checksumFailed.length,
    checksumMissing:checksumMissing.length,
    points:points.slice(0,2000),
    jumps,
    timeRollbacks,
    speedMismatches,
    satelliteJumps:satJumps,
    findings,
    nextActions,
    notes:['NMEA 异常只能说明定位数据不一致；确认 GPS spoof/jamming 需要与接收机状态、RF/SDR、飞控时间线或独立传感器交叉验证。']
  };
}

module.exports={ checksumNmea, verifyChecksum, parseCoord, parseNmea, haversineMeters, analyzeGnssLog };
