'use strict';

const {nativeImage}=require('electron');
const {decodePng,MAX_IMAGE_PIXELS,MAX_IMAGE_BYTES}=require('../core/ai_image_preprocess_executor');

async function decodeImageWithElectron(request={}){
  const buffer=Buffer.isBuffer(request.buffer)?request.buffer:Buffer.from(request.buffer||[]);
  if(!buffer.length||buffer.length>MAX_IMAGE_BYTES)throw new Error(`图片输入大小 ${buffer.length} 超出安全范围`);
  const image=nativeImage.createFromBuffer(buffer);
  if(!image||image.isEmpty())throw new Error(`${request.file||'image'}: Chromium 图片解码失败`);
  const size=image.getSize();const width=Number(size.width),height=Number(size.height);const maxPixels=Math.min(Number(request.maxPixels)||MAX_IMAGE_PIXELS,MAX_IMAGE_PIXELS);
  if(!Number.isSafeInteger(width)||!Number.isSafeInteger(height)||width<=0||height<=0||width*height>maxPixels)throw new Error(`${request.file||'image'}: decoded ${width}x${height} 超出像素上限`);
  const png=image.toPNG();
  const decoded=decodePng(png,{maxBytes:MAX_IMAGE_BYTES});
  decoded.source={format:'electron-nativeImage->png',inputExtension:request.extension||null,width,height};
  return decoded;
}

module.exports={decodeImageWithElectron};
