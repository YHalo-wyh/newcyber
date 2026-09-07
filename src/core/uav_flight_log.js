function splitCsv(line) {
  const out=[]; let cur=''; let quoted=false;
  for (let i=0;i<line.length;i+=1) {
    const c=line[i];
    if (c==='"') { quoted=!quoted; continue; }
    if (c===',' && !quoted) { out.push(cur.trim()); cur=''; }
    else cur+=c;
  }
  out.push(cur.trim());
  return out;
}

function numeric(value) {
  const n=Number(value);
  return Number.isFinite(n) ? n : null;
}

function analyzeDataFlashText(text) {
  const lines=String(text||'').split(/\r?\n/).filter((x)=>x.trim());
  const formats=new Map();
  const rows=[];
  const counts={};
  for (const [lineIndex,line] of lines.entries()) {
    const parts=splitCsv(line);
    if (!parts.length) continue;
    const type=parts[0].trim();
    if (type==='FMT' && parts.length>=6) {
      const name=parts[3];
      const columns=parts.slice(5).join(',').split(',').map((x)=>x.trim()).filter(Boolean);
      formats.set(name,{ typeId:numeric(parts[1]), length:numeric(parts[2]), format:parts[4], columns });
      continue;
    }
    counts[type]=(counts[type]||0)+1;
    const fmt=formats.get(type);
    const obj={ type, line:lineIndex+1, raw:line.slice(0,500) };
    if (fmt) {
      for (let i=0;i<fmt.columns.length && i+1<parts.length;i+=1) obj[fmt.columns[i]]=numeric(parts[i+1]) ?? parts[i+1];
    } else {
      obj.values=parts.slice(1).map((x)=>numeric(x) ?? x);
    }
    rows.push(obj);
  }

  const modes=rows.filter((r)=>r.type==='MODE').slice(0,500);
  const params=rows.filter((r)=>r.type==='PARM' || r.type==='PARAM').slice(0,2000);
  const gps=rows.filter((r)=>/^GPS\d*$/.test(r.type)).slice(0,5000);
  const attitude=rows.filter((r)=>/^(ATT|AHR2|XKF1)$/.test(r.type)).slice(0,5000);
  const events=rows.filter((r)=>/^(ERR|EV|EVENT|MSG|STAT)$/.test(r.type)).slice(0,2000);

  function timeValue(row) {
    const us=numeric(row.TimeUS ?? row.TimeUsec);
    if (us!=null) return us/1e6;
    const ms=numeric(row.TimeMS ?? row.TimeMs);
    if (ms!=null) return ms/1e3;
    return null;
  }
  const times=rows.map(timeValue).filter((x)=>x!=null);
  const timeRange=times.length ? { startSec:Math.min(...times), endSec:Math.max(...times), durationSec:Math.max(...times)-Math.min(...times) } : null;

  const findings=[];
  if (params.some((r)=>/^FENCE_|GEOFENCE/i.test(String(r.Name ?? r.ParamName ?? r.values?.[0] ?? '')))) findings.push({ id:'flightlog-geofence-param', severity:'info', evidence:'FENCE_/GEOFENCE parameter records present', meaning:'飞行日志中存在地理围栏参数，可与 PARAM_SET 抓包或任务配置做前后对比。' });
  if (events.some((r)=>/fail|error|prearm|ekf|gps|fence/i.test(r.raw))) findings.push({ id:'flightlog-safety-event', severity:'medium', evidence:`events=${events.length}`, meaning:'日志中存在安全/导航相关事件；按时间线与姿态、GPS、控制命令交叉关联。' });
  if (gps.length) findings.push({ id:'flightlog-gps-track', severity:'info', evidence:`gpsRows=${gps.length}`, meaning:'已提取 GPS 轨迹记录，可用于定位跳变、返航点变化和异常速度。' });
  if (attitude.length) findings.push({ id:'flightlog-attitude-track', severity:'info', evidence:`attitudeRows=${attitude.length}`, meaning:'已提取姿态记录，可与 MAVLink ATTITUDE/IMU 数据做一致性对照。' });

  return {
    format:'ardupilot-dataflash-text',
    lineCount:lines.length,
    messageCounts:counts,
    formats:[...formats.entries()].map(([name,value])=>({name,...value})),
    timeRange,
    modes,
    params,
    gps,
    attitude,
    events,
    findings,
    notes:['DataFlash 文本解析只依据 FMT/CSV 结构，不执行日志中任何内容；未知消息保留原始行。']
  };
}

function analyzeFlightLog(input) {
  const buffer=Buffer.isBuffer(input) ? input : Buffer.from(String(input||''),'utf8');
  if (buffer.length>=8 && buffer.subarray(0,4).toString('ascii')==='ULog') {
    return {
      format:'px4-ulog',
      size:buffer.length,
      version:buffer[7] ?? null,
      messageCounts:{}, modes:[], params:[], gps:[], attitude:[], events:[], findings:[{ id:'ulog-detected', severity:'info', evidence:`size=${buffer.length}`, meaning:'识别到 PX4 ULog 容器；当前仅做安全识别，后续应由专用 ULog message parser 展开。' }],
      notes:['未对 ULog payload 做猜测式解码。']
    };
  }
  const text=buffer.toString('utf8');
  if (/^FMT\s*,/m.test(text) || /^(?:ATT|GPS|MODE|PARM|ERR|EV)\s*,/m.test(text)) return analyzeDataFlashText(text);
  return { format:'unknown', size:buffer.length, messageCounts:{}, modes:[], params:[], gps:[], attitude:[], events:[], findings:[], notes:['未识别为 ArduPilot DataFlash 文本或 PX4 ULog。'] };
}

module.exports={ splitCsv, analyzeDataFlashText, analyzeFlightLog };
