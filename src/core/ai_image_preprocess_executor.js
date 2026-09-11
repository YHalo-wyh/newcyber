'use strict';

const zlib=require('node:zlib');

const PNG_SIGNATURE='89504e470d0a1a0a';
const MAX_IMAGE_PIXELS=20_000_000;
const MAX_IMAGE_BYTES=64*1024*1024;
const SUPPORTED_DTYPES=new Set(['float32','float64','uint8']);

function assertFinitePositive(value,label){const n=Number(value);if(!Number.isFinite(n)||n<=0)throw new Error(`${label} 必须为正数`);return n;}
function product(values){let total=1;for(const value of values){const n=Number(value);if(!Number.isSafeInteger(n)||n<=0)throw new Error('tensor dims 必须为正整数');total*=n;if(!Number.isSafeInteger(total)||total>40_000_000)throw new Error('tensor 元素数量超过图像执行器上限');}return total;}
function staticDimension(value){const n=Number(value);return Number.isInteger(n)&&n>0?n:null;}
function paeth(a,b,c){const p=a+b-c,pa=Math.abs(p-a),pb=Math.abs(p-b),pc=Math.abs(p-c);return pa<=pb&&pa<=pc?a:pb<=pc?b:c;}

function decodePng(buffer,options={}){
  if(!Buffer.isBuffer(buffer))buffer=Buffer.from(buffer||[]);
  const maxBytes=Number(options.maxBytes)||MAX_IMAGE_BYTES;if(buffer.length<33||buffer.length>maxBytes)throw new Error(`PNG 大小 ${buffer.length} 超出安全范围`);
  if(buffer.subarray(0,8).toString('hex')!==PNG_SIGNATURE)throw new Error('不是 PNG 数据');
  let offset=8,width=null,height=null,bitDepth=null,colorType=null,interlace=null,palette=null,transparency=null;const idat=[];
  while(offset+12<=buffer.length){
    const length=buffer.readUInt32BE(offset);const type=buffer.subarray(offset+4,offset+8).toString('ascii');const start=offset+8,end=start+length;
    if(length>MAX_IMAGE_BYTES||end+4>buffer.length)throw new Error(`PNG chunk ${type} 长度异常`);
    const data=buffer.subarray(start,end);offset=end+4;
    if(type==='IHDR'){
      if(length!==13)throw new Error('PNG IHDR 长度异常');width=data.readUInt32BE(0);height=data.readUInt32BE(4);bitDepth=data[8];colorType=data[9];
      if(data[10]!==0||data[11]!==0)throw new Error('PNG compression/filter method 不受支持');interlace=data[12];
      if(!width||!height||width*height>MAX_IMAGE_PIXELS)throw new Error(`PNG 像素数 ${width}x${height} 超出上限`);
    }else if(type==='PLTE')palette=Buffer.from(data);
    else if(type==='tRNS')transparency=Buffer.from(data);
    else if(type==='IDAT')idat.push(Buffer.from(data));
    else if(type==='IEND')break;
  }
  if(!width||!height||!idat.length)throw new Error('PNG 缺少 IHDR/IDAT');
  if(bitDepth!==8)throw new Error(`自动图像执行仅支持 8-bit PNG，当前 bitDepth=${bitDepth}`);
  if(interlace!==0)throw new Error('自动图像执行暂不接受 interlaced PNG');
  const channels={0:1,2:3,3:1,4:2,6:4}[colorType];if(!channels)throw new Error(`PNG colorType=${colorType} 不受支持`);
  if(colorType===3&&(!palette||palette.length<3))throw new Error('indexed PNG 缺少 palette');
  const stride=width*channels,expected=(stride+1)*height;
  const inflated=zlib.inflateSync(Buffer.concat(idat),{maxOutputLength:expected+1024});if(inflated.length!==expected)throw new Error(`PNG 解压长度 ${inflated.length} 与期望 ${expected} 不一致`);
  const raw=Buffer.allocUnsafe(stride*height);let src=0;
  for(let y=0;y<height;y+=1){
    const filter=inflated[src++],row=y*stride,prev=row-stride;
    for(let x=0;x<stride;x+=1){
      const value=inflated[src++],left=x>=channels?raw[row+x-channels]:0,up=y?raw[prev+x]:0,upLeft=y&&x>=channels?raw[prev+x-channels]:0;
      if(filter===0)raw[row+x]=value;
      else if(filter===1)raw[row+x]=(value+left)&255;
      else if(filter===2)raw[row+x]=(value+up)&255;
      else if(filter===3)raw[row+x]=(value+Math.floor((left+up)/2))&255;
      else if(filter===4)raw[row+x]=(value+paeth(left,up,upLeft))&255;
      else throw new Error(`PNG filter=${filter} 不受支持`);
    }
  }
  const rgba=new Uint8Array(width*height*4);
  for(let i=0,p=0;i<width*height;i+=1,p+=4){
    const base=i*channels;
    if(colorType===6){rgba[p]=raw[base];rgba[p+1]=raw[base+1];rgba[p+2]=raw[base+2];rgba[p+3]=raw[base+3];}
    else if(colorType===2){rgba[p]=raw[base];rgba[p+1]=raw[base+1];rgba[p+2]=raw[base+2];rgba[p+3]=255;}
    else if(colorType===0){const g=raw[base];rgba[p]=g;rgba[p+1]=g;rgba[p+2]=g;rgba[p+3]=255;}
    else if(colorType===4){const g=raw[base];rgba[p]=g;rgba[p+1]=g;rgba[p+2]=g;rgba[p+3]=raw[base+1];}
    else {const idx=raw[base],q=idx*3;if(q+2>=palette.length)throw new Error('PNG palette index 越界');rgba[p]=palette[q];rgba[p+1]=palette[q+1];rgba[p+2]=palette[q+2];rgba[p+3]=transparency&&idx<transparency.length?transparency[idx]:255;}
  }
  return{schema:'newcyber.decoded-image.v1',width,height,rgba,source:{format:'png',bitDepth,colorType}};
}

function resizeRgba(image,targetWidth,targetHeight,mode='bilinear'){
  const width=Math.round(assertFinitePositive(targetWidth,'width')),height=Math.round(assertFinitePositive(targetHeight,'height'));
  if(width*height>MAX_IMAGE_PIXELS)throw new Error('resize 后像素数超过上限');
  if(width===image.width&&height===image.height)return{...image,rgba:new Uint8Array(image.rgba)};
  const out=new Uint8Array(width*height*4),src=image.rgba,sw=image.width,sh=image.height;
  if(mode==='nearest'){
    for(let y=0;y<height;y+=1){const sy=Math.min(sh-1,Math.max(0,Math.floor((y+0.5)*sh/height)));
      for(let x=0;x<width;x+=1){const sx=Math.min(sw-1,Math.max(0,Math.floor((x+0.5)*sw/width))),a=(sy*sw+sx)*4,b=(y*width+x)*4;out[b]=src[a];out[b+1]=src[a+1];out[b+2]=src[a+2];out[b+3]=src[a+3];}}
  }else if(mode==='bilinear'){
    for(let y=0;y<height;y+=1){const fy=(y+0.5)*sh/height-0.5,y0=Math.max(0,Math.floor(fy)),y1=Math.min(sh-1,y0+1),wy=Math.max(0,Math.min(1,fy-y0));
      for(let x=0;x<width;x+=1){const fx=(x+0.5)*sw/width-0.5,x0=Math.max(0,Math.floor(fx)),x1=Math.min(sw-1,x0+1),wx=Math.max(0,Math.min(1,fx-x0)),b=(y*width+x)*4;
        for(let c=0;c<4;c+=1){const p00=src[(y0*sw+x0)*4+c],p01=src[(y0*sw+x1)*4+c],p10=src[(y1*sw+x0)*4+c],p11=src[(y1*sw+x1)*4+c];out[b+c]=Math.max(0,Math.min(255,Math.round((p00*(1-wx)+p01*wx)*(1-wy)+(p10*(1-wx)+p11*wx)*wy)));}}}
  }else throw new Error(`不支持 interpolation=${mode}`);
  return{...image,width,height,rgba:out};
}

function centerCropRgba(image,targetWidth,targetHeight){
  const width=Math.round(assertFinitePositive(targetWidth,'crop width')),height=Math.round(assertFinitePositive(targetHeight,'crop height'));
  if(width>image.width||height>image.height)throw new Error(`CenterCrop ${width}x${height} 大于当前图像 ${image.width}x${image.height}`);
  const left=Math.floor((image.width-width)/2),top=Math.floor((image.height-height)/2),out=new Uint8Array(width*height*4);
  for(let y=0;y<height;y+=1){const srcStart=((top+y)*image.width+left)*4,dst=y*width*4;out.set(image.rgba.subarray(srcStart,srcStart+width*4),dst);}
  return{...image,width,height,rgba:out};
}

function chosenEvidence(manifest,kind){const rows=(manifest?.evidence||[]).filter((item)=>item.kind===kind);const selected=manifest?.pipeline?.[kind==='size'?'size':kind];return rows.filter((row)=>JSON.stringify(row.value)===JSON.stringify(selected));}
function resizeMode(manifest){
  const explicit=String(manifest?.pipeline?.interpolation||'').toLowerCase();if(['nearest','bilinear'].includes(explicit))return{mode:explicit,source:'manifest'};
  const rows=chosenEvidence(manifest,'size');
  if(rows.some((row)=>/torchvision\/PIL Resize|cv2\.resize/i.test(String(row.detail||''))))return{mode:'bilinear',source:'known-library-default'};
  throw new Error('缺少可证明的 resize interpolation；拒绝猜测 nearest/bilinear');
}
function spatialPlan(manifest){
  const size=manifest?.pipeline?.size||null,crop=manifest?.pipeline?.crop||null;if(!size&&!crop)return[];
  if(crop?.type==='random')throw new Error('RandomCrop 没有确定 seed，不能自动执行');
  const resizeStep=size?{op:'resize',height:Number(size.height),width:Number(size.width)}:null;
  const cropStep=crop?{op:'center-crop',height:Number(crop.height),width:Number(crop.width)}:null;
  if(!resizeStep)return[cropStep];if(!cropStep)return[resizeStep];
  const sizeRows=chosenEvidence(manifest,'size'),cropRows=chosenEvidence(manifest,'crop');
  for(const a of sizeRows)for(const b of cropRows)if(a.file===b.file&&Number.isInteger(a.line)&&Number.isInteger(b.line))return a.line<=b.line?[resizeStep,cropStep]:[cropStep,resizeStep];
  throw new Error('Resize 与 Crop 来自不同证据源，空间操作顺序不确定');
}

function modelChannelCount(metadata){
  const dims=metadata?.dimensions;if(!Array.isArray(dims))return null;
  if(dims.length===4){const c1=staticDimension(dims[1]),c3=staticDimension(dims[3]);if([1,3,4].includes(c1))return c1;if([1,3,4].includes(c3))return c3;}
  if(dims.length===3){const c0=staticDimension(dims[0]),c2=staticDimension(dims[2]);if([1,3,4].includes(c0))return c0;if([1,3,4].includes(c2))return c2;}
  return null;
}
function colorMode(manifest,metadata){const value=String(manifest?.pipeline?.color||'').toUpperCase();if(['RGB','BGR','GRAY'].includes(value))return{mode:value,source:'manifest'};if(modelChannelCount(metadata)===1)return{mode:'GRAY',source:'model-contract'};throw new Error('三通道图像缺少 RGB/BGR 证据，拒绝猜测颜色顺序');}
function channelCount(mode){return mode==='GRAY'?1:3;}

function pixelChannels(image,mode){
  const channels=channelCount(mode),out=new Float64Array(image.width*image.height*channels);
  for(let i=0,j=0;i<image.width*image.height;i+=1){const p=i*4,r=image.rgba[p],g=image.rgba[p+1],b=image.rgba[p+2];
    if(mode==='RGB'){out[j++]=r;out[j++]=g;out[j++]=b;}
    else if(mode==='BGR'){out[j++]=b;out[j++]=g;out[j++]=r;}
    else out[j++]=0.299*r+0.587*g+0.114*b;
  }
  return{values:out,channels};
}
function applyScaleNormalize(values,channels,manifest){
  const scale=manifest?.pipeline?.scale||null,norm=manifest?.pipeline?.normalize||null,out=new Float64Array(values.length);
  const factor=scale&&Number.isFinite(Number(scale.factor))?Number(scale.factor):null;
  for(let i=0;i<values.length;i+=1){let value=values[i];if(scale){if(factor!==null)value*=factor;else if(scale.to==='-1..1')value=value/127.5-1;else throw new Error(`无法执行 scale=${JSON.stringify(scale)}`);}if(norm){const c=i%channels,mean=Number(norm.mean?.[c]),std=Number(norm.std?.[c]);if(!Number.isFinite(mean)||!Number.isFinite(std)||std===0)throw new Error('Normalize mean/std 与 channel 数不匹配');value=(value-mean)/std;}out[i]=value;}
  return out;
}
function reorder(values,width,height,channels,layout){
  const upper=String(layout||'').toUpperCase();if(!['HWC','CHW','NHWC','NCHW'].includes(upper))throw new Error(`layout=${layout} 不受支持`);
  const base=upper.startsWith('N')?upper.slice(1):upper;if(base==='HWC')return{values,dims:[height,width,channels],layout:upper};
  const out=new Float64Array(values.length);for(let c=0;c<channels;c+=1)for(let y=0;y<height;y+=1)for(let x=0;x<width;x+=1)out[(c*height+y)*width+x]=values[(y*width+x)*channels+c];
  return{values:out,dims:[channels,height,width],layout:upper};
}
function typedPayload(values,dtype){
  const type=String(dtype||'').toLowerCase();if(!SUPPORTED_DTYPES.has(type))throw new Error(`图像执行器暂不支持 dtype=${dtype}`);
  let array;if(type==='float32')array=Float32Array.from(values);else if(type==='float64')array=Float64Array.from(values);else array=Uint8Array.from(values,(v)=>Math.max(0,Math.min(255,Math.round(v))));
  return{type,array,base64:Buffer.from(array.buffer,array.byteOffset,array.byteLength).toString('base64')};
}
function adaptImageDims(dims,layout,manifest,metadata){
  let out=dims.slice(),adaptation='exact-layout';const wantsBatch=String(layout).startsWith('N')||manifest?.pipeline?.batch==='prepend-axis';if(wantsBatch)out=[1,...out];
  const expected=metadata?.dimensions;if(Array.isArray(expected)&&expected.length){
    if(out.length===expected.length&&out.every((value,index)=>staticDimension(expected[index])===null||staticDimension(expected[index])===value))return{dims:out,adaptation:wantsBatch?'manifest-batch':'exact-shape'};
    if(!wantsBatch&&expected.length===out.length+1&&(staticDimension(expected[0])===null||staticDimension(expected[0])===1)){
      const expanded=[1,...out];if(expanded.every((value,index)=>staticDimension(expected[index])===null||staticDimension(expected[index])===value))return{dims:expanded,adaptation:'prepend-model-batch-1'};
    }
    throw new Error(`预处理输出 shape ${JSON.stringify(out)} 与模型输入 ${JSON.stringify(expected)} 不兼容`);
  }
  return{dims:out,adaptation:wantsBatch?'manifest-batch':'metadata-unavailable'};
}

function preprocessDecodedImage(image,manifest,metadata=null){
  if(!image||!Number.isInteger(image.width)||!Number.isInteger(image.height)||!(image.rgba instanceof Uint8Array))throw new Error('decoded image 格式无效');
  if(!manifest||manifest.executionReady!==true||manifest.status!=='ready')throw new Error(`preprocessing manifest 未 ready: ${manifest?.status||'missing'}`);
  let current={...image,rgba:new Uint8Array(image.rgba)},interpolation=null;const trace=[];
  for(const step of spatialPlan(manifest)){
    if(step.op==='resize'){interpolation=resizeMode(manifest);current=resizeRgba(current,step.width,step.height,interpolation.mode);trace.push({...step,interpolation:interpolation.mode,evidence:interpolation.source});}
    else{current=centerCropRgba(current,step.width,step.height);trace.push(step);}
  }
  const color=colorMode(manifest,metadata);const channelData=pixelChannels(current,color.mode);trace.push({op:'color',mode:color.mode,evidence:color.source});
  const scaled=applyScaleNormalize(channelData.values,channelData.channels,manifest);if(manifest.pipeline.scale)trace.push({op:'scale',value:manifest.pipeline.scale});if(manifest.pipeline.normalize)trace.push({op:'normalize',value:manifest.pipeline.normalize});
  const ordered=reorder(scaled,current.width,current.height,channelData.channels,manifest.pipeline.layout);const adapted=adaptImageDims(ordered.dims,ordered.layout,manifest,metadata);const payload=typedPayload(ordered.values,manifest.pipeline.dtype);
  if(product(adapted.dims)!==payload.array.length)throw new Error('图像 tensor dims 与 payload 数量不一致');
  return{schema:'newcyber.image-tensor.v1',type:payload.type,dims:adapted.dims,base64:payload.base64,shape:{width:current.width,height:current.height,channels:channelData.channels,layout:ordered.layout},adaptation:adapted.adaptation,trace,backend:{decoder:image.source?.format||'injected',resize:interpolation?`newcyber-${interpolation.mode}-v1`:null,exactReferenceLibrary:false}};
}

function preprocessPngToTensor(buffer,manifest,metadata=null,options={}){return preprocessDecodedImage(decodePng(buffer,options),manifest,metadata);}

module.exports={MAX_IMAGE_PIXELS,MAX_IMAGE_BYTES,decodePng,resizeRgba,centerCropRgba,spatialPlan,preprocessDecodedImage,preprocessPngToTensor};
