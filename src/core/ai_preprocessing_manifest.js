'use strict';

const REQUIRED_FOR_IMAGE_EXECUTION=['size','layout','scale','dtype'];

function list(value){return Array.isArray(value)?value:[];}
function text(value){return String(value??'');}
function numberList(raw){
  const values=String(raw||'').split(',').map((x)=>Number(x.trim())).filter(Number.isFinite);
  return values.length?values:null;
}
function lineOf(source,index){return source.slice(0,index).split(/\r?\n/).length;}
function clip(value,limit=220){return String(value||'').replace(/\s+/g,' ').trim().slice(0,limit);}

function evidence(file,source,index,kind,value,confidence='exact-source',detail=''){
  const line=lineOf(source,index);const lines=source.split(/\r?\n/);const excerpt=clip(lines[Math.max(0,line-1)]||'');
  return {file,line,kind,value,confidence,detail:detail||null,excerpt};
}

function add(rows,item){
  const key=`${item.kind}:${JSON.stringify(item.value)}:${item.file}:${item.line}`;
  if(!rows.some((x)=>x._key===key))rows.push({...item,_key:key});
}

function scanSource(file,source){
  const rows=[];const patterns=[];
  const push=(kind,value,match,confidence='exact-source',detail='')=>add(rows,evidence(file,source,match.index,kind,value,confidence,detail));
  let match;

  const tupleResize=/(?:transforms\.)?Resize\s*\(\s*\(?\s*(\d{2,4})\s*[,x]\s*(\d{2,4})\s*\)?\s*\)|cv2\.resize\s*\([^\n]{0,240}?\(\s*(\d{2,4})\s*,\s*(\d{2,4})\s*\)/gi;
  while((match=tupleResize.exec(source))){const a=Number(match[1]||match[3]),b=Number(match[2]||match[4]);if(a&&b)push('size',{height:a,width:b},match,'exact-source','显式 resize 尺寸');}
  const scalarResize=/(?:transforms\.)?Resize\s*\(\s*(\d{2,4})\s*\)/gi;
  while((match=scalarResize.exec(source)))push('resize-short-edge',Number(match[1]),match,'exact-source','单值 Resize 只约束短边，不能直接当最终 H×W');
  const crop=/(?:CenterCrop|RandomCrop)\s*\(\s*\(?\s*(\d{2,4})(?:\s*,\s*(\d{2,4}))?\s*\)?\s*\)/gi;
  while((match=crop.exec(source))){const h=Number(match[1]),w=Number(match[2]||match[1]);push('crop',{height:h,width:w,type:/CenterCrop/i.test(match[0])?'center':'random'},match);}

  const normalize=/(?:transforms\.)?Normalize\s*\(\s*(?:mean\s*=\s*)?\[([^\]]+)\]\s*,\s*(?:std\s*=\s*)?\[([^\]]+)\]/gi;
  while((match=normalize.exec(source))){const mean=numberList(match[1]),std=numberList(match[2]);if(mean&&std)push('normalize',{mean,std},match);}
  const namedMeanStd=/mean\s*=\s*(?:np\.(?:array|asarray)\s*\()?\[([^\]]+)\][^\n]{0,160}?std\s*=\s*(?:np\.(?:array|asarray)\s*\()?\[([^\]]+)\]/gi;
  while((match=namedMeanStd.exec(source))){const mean=numberList(match[1]),std=numberList(match[2]);if(mean&&std)push('normalize',{mean,std},match,'derived','同一上下文声明 mean/std，需与实际 preprocessing 调用核对');}

  const colorRules=[
    [/cv2\.COLOR_BGR2RGB/gi,'RGB','cv2 BGR→RGB'],[/cv2\.COLOR_RGB2BGR/gi,'BGR','cv2 RGB→BGR'],[/\.convert\(\s*["']RGB["']\s*\)/gi,'RGB','PIL convert RGB'],[/\.convert\(\s*["']L["']\s*\)/gi,'GRAY','PIL grayscale']
  ];
  for(const [regex,value,detail] of colorRules)while((match=regex.exec(source)))push('color',value,match,'exact-source',detail);

  const layoutRules=[
    [/\.permute\(\s*2\s*,\s*0\s*,\s*1\s*\)/gi,'CHW'],[/np\.transpose\s*\([^\n]{0,180}?\(\s*2\s*,\s*0\s*,\s*1\s*\)\s*\)/gi,'CHW'],[/\.permute\(\s*0\s*,\s*3\s*,\s*1\s*,\s*2\s*\)/gi,'NCHW'],[/np\.transpose\s*\([^\n]{0,180}?\(\s*0\s*,\s*3\s*,\s*1\s*,\s*2\s*\)\s*\)/gi,'NCHW']
  ];
  for(const [regex,value] of layoutRules)while((match=regex.exec(source)))push('layout',value,match);
  const toTensor=/(?:transforms\.)?ToTensor\s*\(\s*\)/gi;
  while((match=toTensor.exec(source))){push('layout','CHW',match,'derived','torchvision ToTensor 对普通 HWC 图像输出 CHW');push('scale',{from:'0..255',to:'0..1',factor:1/255},match,'derived','torchvision ToTensor 对 uint8/PIL 图像执行 1/255 缩放');push('dtype','float32',match,'derived','torchvision ToTensor 常规输出 float tensor');}

  const scale255=/(?:\/\s*255(?:\.0+)?\b|\*\s*\(\s*1(?:\.0+)?\s*\/\s*255(?:\.0+)?\s*\)|\*\s*0\.0039215686)/gi;
  while((match=scale255.exec(source)))push('scale',{from:'0..255',to:'0..1',factor:1/255},match);
  const scale127=/(?:\/\s*127\.5\b[^\n]{0,80}?-\s*1|\-\s*127\.5[^\n]{0,80}?\/\s*127\.5)/gi;
  while((match=scale127.exec(source)))push('scale',{from:'0..255',to:'-1..1'},match,'derived','常见 [-1,1] 图像缩放表达式');

  const dtypeRules=[
    [/\.astype\(\s*(?:np\.)?float32\s*\)/gi,'float32'],[/\.astype\(\s*(?:np\.)?float64\s*\)/gi,'float64'],[/\.float\(\s*\)/gi,'float32'],[/torch\.float32\b/gi,'float32'],[/torch\.float64\b/gi,'float64']
  ];
  for(const [regex,value] of dtypeRules)while((match=regex.exec(source)))push('dtype',value,match);

  const batchRules=[[/\.unsqueeze\(\s*0\s*\)/gi,'prepend-axis'],[/np\.expand_dims\s*\([^\n]{0,160}?(?:axis\s*=\s*0|,\s*0\s*\))/gi,'prepend-axis'],[/\[[Nn]one\s*,/g,'prepend-axis']];
  for(const [regex,value] of batchRules)while((match=regex.exec(source)))push('batch',value,match);

  const inputShape=/(?:input[_ ]?shape|image[_ ]?shape|img[_ ]?size|input[_ ]?size)\s*[=:]\s*[\[(]\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*(\d+))?/gi;
  while((match=inputShape.exec(source))){
    const dims=[match[1],match[2],match[3],match[4]].filter(Boolean).map(Number);
    if(dims.length===4){
      if(dims[1]===1||dims[1]===3||dims[1]===4){push('shape',{dims,layout:'NCHW'},match,'derived','shape 中第二维像 channel');push('layout','NCHW',match,'derived');push('size',{height:dims[2],width:dims[3]},match,'derived');}
      else if(dims[3]===1||dims[3]===3||dims[3]===4){push('shape',{dims,layout:'NHWC'},match,'derived','shape 末维像 channel');push('layout','NHWC',match,'derived');push('size',{height:dims[1],width:dims[2]},match,'derived');}
    }else if(dims.length===3){
      if(dims[0]===1||dims[0]===3||dims[0]===4){push('shape',{dims,layout:'CHW'},match,'derived');push('layout','CHW',match,'derived');push('size',{height:dims[1],width:dims[2]},match,'derived');}
      else if(dims[2]===1||dims[2]===3||dims[2]===4){push('shape',{dims,layout:'HWC'},match,'derived');push('layout','HWC',match,'derived');push('size',{height:dims[0],width:dims[1]},match,'derived');}
    }
  }

  const preprocessTokens=/(?:preprocess|transform|Resize|Normalize|ToTensor|cv2\.resize|permute|transpose|astype|unsqueeze|onnxruntime|InferenceSession)/gi;
  while((match=preprocessTokens.exec(source)))patterns.push({file,line:lineOf(source,match.index),token:match[0],excerpt:clip(source.split(/\r?\n/)[lineOf(source,match.index)-1]||'')});
  return{evidence:rows.map(({_key,...item})=>item),signals:patterns.slice(0,80)};
}

function keyValue(value){return JSON.stringify(value);}
function resolveKind(evidenceRows,kind){
  const rows=evidenceRows.filter((item)=>item.kind===kind);if(!rows.length)return{value:null,status:'missing',evidence:[]};
  const groups=new Map();for(const row of rows){const key=keyValue(row.value);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(row);}
  const ranked=[...groups.entries()].map(([key,items])=>({key,value:items[0].value,items,score:items.reduce((sum,item)=>sum+(item.confidence==='exact-source'?3:item.confidence==='derived'?2:1),0)})).sort((a,b)=>b.score-a.score||b.items.length-a.items.length);
  const best=ranked[0];const conflict=ranked.length>1&&ranked[1].score>=best.score*0.75;
  return{value:best.value,status:conflict?'conflict':'resolved',evidence:best.items,alternatives:ranked.slice(1,4).map((item)=>({value:item.value,score:item.score,evidence:item.items.slice(0,3)}))};
}

function buildPreprocessingManifest(sources,options={}){
  const scanned=[];let allEvidence=[];let allSignals=[];
  for(const source of list(sources)){
    const file=text(source.file||source.path||'source');const body=text(source.text||source.content);
    if(!body)continue;
    const result=scanSource(file,body);scanned.push({file,bytes:Buffer.byteLength(body),evidence:result.evidence.length,signals:result.signals.length});
    allEvidence=allEvidence.concat(result.evidence);allSignals=allSignals.concat(result.signals);
  }
  const resolved={};for(const kind of ['size','resize-short-edge','crop','color','layout','scale','normalize','dtype','batch','shape'])resolved[kind]=resolveKind(allEvidence,kind);
  const missing=REQUIRED_FOR_IMAGE_EXECUTION.filter((kind)=>resolved[kind].status==='missing');
  const conflicts=Object.entries(resolved).filter(([,value])=>value.status==='conflict').map(([kind,value])=>({kind,value:value.value,alternatives:value.alternatives}));
  const evidenceCount=allEvidence.length;
  const status=!evidenceCount?'not-detected':conflicts.length?'conflict':missing.length?'partial':'ready';
  const confidence=status==='ready'?'high':status==='partial'?'medium':status==='conflict'?'low':'none';
  const manifest={
    schema:'newcyber.ai-preprocessing-manifest.v1',status,confidence,executionReady:status==='ready',
    pipeline:{
      size:resolved.size.value,resizeShortEdge:resolved['resize-short-edge'].value,crop:resolved.crop.value,color:resolved.color.value,
      layout:resolved.layout.value,scale:resolved.scale.value,normalize:resolved.normalize.value,dtype:resolved.dtype.value,batch:resolved.batch.value,shape:resolved.shape.value
    },
    missing,conflicts,
    evidence:allEvidence.slice(0,160),signals:allSignals.slice(0,120),sources:scanned,
    notes:[
      '所有 preprocessing 字段都必须能回溯到源码/配置证据；不会仅凭模型名称或常见架构默认 ImageNet mean/std。',
      'ready 只表示预处理参数证据足够，不表示模型输出或对抗样本结论已经验证。',
      '同一字段出现强冲突时状态为 conflict，自动执行器应停止而不是猜一个值。'
    ]
  };
  if(options.requireColor&&resolved.color.status==='missing'){manifest.missing.push('color');manifest.status='partial';manifest.executionReady=false;manifest.confidence='medium';}
  return manifest;
}

module.exports={REQUIRED_FOR_IMAGE_EXECUTION,scanSource,buildPreprocessingManifest};
