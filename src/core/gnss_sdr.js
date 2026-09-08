const BANDS=Object.freeze([
  {id:'GPS-L1/Galileo-E1',centerHz:1575.42e6,halfWidthHz:2.5e6},
  {id:'BeiDou-B1I',centerHz:1561.098e6,halfWidthHz:2.5e6},
  {id:'GPS-L2',centerHz:1227.60e6,halfWidthHz:2.5e6},
  {id:'GPS-L5/Galileo-E5a',centerHz:1176.45e6,halfWidthHz:2.5e6},
  {id:'GLONASS-L1',centerHz:1602.0e6,halfWidthHz:8e6}
]);

function median(values) {
  if (!values.length) return null;
  const s=[...values].sort((a,b)=>a-b); const m=Math.floor(s.length/2);
  return s.length%2?s[m]:(s[m-1]+s[m])/2;
}

function parseSpectrum(input) {
  if (Array.isArray(input)) return input.map((r)=>({frequencyHz:Number(r.frequencyHz??r.frequency??r.freq_hz??r.freq),powerDb:Number(r.powerDb??r.power_db??r.power??r.db)})).filter((r)=>Number.isFinite(r.frequencyHz)&&Number.isFinite(r.powerDb));
  const text=String(input||'').trim();
  if (!text) throw new Error('请输入 SDR/FFT CSV：frequency_hz,power_db');
  if (/^[\[{]/.test(text)) {
    const parsed=JSON.parse(text); return parseSpectrum(Array.isArray(parsed)?parsed:parsed.rows||parsed.samples||[]);
  }
  const lines=text.split(/\r?\n/).filter((x)=>x.trim());
  if (lines.length<2) throw new Error('频谱 CSV 至少需要两行');
  const delimiter=(lines[0].match(/\t/g)||[]).length>(lines[0].match(/,/g)||[]).length?'\t':',';
  const headers=lines[0].split(delimiter).map((x)=>x.trim().toLowerCase());
  const fi=headers.findIndex((x)=>/(?:frequency|freq)(?:_hz)?/.test(x));
  const pi=headers.findIndex((x)=>/(?:power|dbm|power_db|level)/.test(x));
  if (fi<0||pi<0) throw new Error('频谱表头需要 frequency/freq 与 power/dbm 列');
  return lines.slice(1).map((line)=>line.split(delimiter)).map((v)=>({frequencyHz:Number(v[fi]),powerDb:Number(v[pi])})).filter((r)=>Number.isFinite(r.frequencyHz)&&Number.isFinite(r.powerDb));
}

function bandStats(samples,band) {
  const inside=samples.filter((s)=>Math.abs(s.frequencyHz-band.centerHz)<=band.halfWidthHz);
  if (inside.length<3) return null;
  const side=samples.filter((s)=>{
    const d=Math.abs(s.frequencyHz-band.centerHz);
    return d>band.halfWidthHz&&d<=band.halfWidthHz*3;
  });
  const baseline=median((side.length>=3?side:samples).map((x)=>x.powerDb));
  const powers=inside.map((x)=>x.powerDb);
  const peak=inside.reduce((a,b)=>b.powerDb>a.powerDb?b:a,inside[0]);
  const med=median(powers);
  const mean=powers.reduce((a,b)=>a+b,0)/powers.length;
  const above6=inside.filter((x)=>x.powerDb>baseline+6).length/inside.length;
  return {id:band.id,centerHz:band.centerHz,samples:inside.length,baselineDb:baseline,medianDb:med,meanDb:mean,peakDb:peak.powerDb,peakHz:peak.frequencyHz,peakAboveBaselineDb:peak.powerDb-baseline,medianAboveBaselineDb:med-baseline,fractionAbove6Db:above6};
}

function analyzeGnssSpectrum(input,options={}) {
  const samples=parseSpectrum(input).sort((a,b)=>a.frequencyHz-b.frequencyHz);
  if (samples.length<5) throw new Error('有效频谱采样点不足');
  const spans={minHz:samples[0].frequencyHz,maxHz:samples[samples.length-1].frequencyHz};
  const stats=BANDS.map((b)=>bandStats(samples,b)).filter(Boolean);
  const findings=[];
  const narrowThreshold=Number(options.narrowbandThresholdDb)||12;
  const wideThreshold=Number(options.widebandThresholdDb)||6;
  for (const s of stats) {
    if (s.peakAboveBaselineDb>=narrowThreshold&&s.fractionAbove6Db<0.35) findings.push({
      id:'gnss-narrowband-interference-candidate',severity:'medium',title:`${s.id} 窄带强峰/干扰候选`,
      evidence:`peak=${(s.peakHz/1e6).toFixed(4)}MHz ${s.peakDb.toFixed(2)}dB, baseline=${s.baselineDb.toFixed(2)}dB, delta=${s.peakAboveBaselineDb.toFixed(2)}dB`,
      meaning:'GNSS 频段内出现相对侧带明显的窄带峰；可能是干扰源、LO 泄漏或采集伪影，需要与多时段/天线断开基线比较。'
    });
    if (s.medianAboveBaselineDb>=wideThreshold||s.fractionAbove6Db>=0.6) findings.push({
      id:'gnss-wideband-noise-rise-candidate',severity:'medium',title:`${s.id} 宽带噪声底抬升候选`,
      evidence:`medianDelta=${s.medianAboveBaselineDb.toFixed(2)}dB, fractionAbove6dB=${(s.fractionAbove6Db*100).toFixed(1)}%`,
      meaning:'GNSS 主频段整体能量抬升，更符合宽带干扰/强邻频泄漏特征；仅凭单次 FFT 不能确认恶意 jamming。'
    });
  }
  if (!stats.length) findings.push({id:'gnss-spectrum-band-not-covered',severity:'info',title:'频谱范围未覆盖内置 GNSS 主频段',evidence:`span=${(spans.minHz/1e6).toFixed(3)}-${(spans.maxHz/1e6).toFixed(3)} MHz`,meaning:'请确认 SDR center frequency/采样率或提供覆盖 L1/L2/L5/B1/GLONASS L1 的 FFT。'});
  const strongest=[...stats].sort((a,b)=>b.peakAboveBaselineDb-a.peakAboveBaselineDb)[0]||null;
  return {
    samples:samples.length,span:spans,bands:stats,strongest,findings,
    nextActions:[
      '将异常频谱窗口与同时间的 NMEA/GGA/RMC、MAVLink GPS_RAW_INT、飞控 EKF/estimator 状态对齐。',
      '对同一 SDR 设置采集“天线接入 / 50Ω 负载 / 已知正常环境”基线，排除设备本底、LO 泄漏和 AGC 变化。',
      '频谱能证明能量异常但不能单独证明 spoofing；欺骗还需码相位/多普勒/卫星一致性或接收机导航解算证据。'
    ],
    notes:['本模块只分析已导出的 FFT/功率谱，不控制 SDR 发射，也不生成欺骗/干扰信号。']
  };
}

module.exports={BANDS,parseSpectrum,bandStats,analyzeGnssSpectrum};
