'use strict';

const fs=require('fs/promises');
const path=require('path');
const zlib=require('zlib');
const crypto=require('crypto');
const {parseTar,extractTarEntry,isTar}=require('./archive_utils');

const DEFAULT_LIMITS=Object.freeze({
  maxArchiveBytes:256*1024*1024,
  maxExpandedBytes:768*1024*1024,
  maxEntryBytes:128*1024*1024,
  maxEntries:3000,
  maxDepth:3,
  maxCompressionRatio:500
});

const ZIP_EXTENSIONS=new Set(['.zip','.jar','.apk','.whl','.ipa','.npz']);
const TAR_EXTENSIONS=new Set(['.tar']);
const GZIP_EXTENSIONS=new Set(['.gz','.tgz']);

function inside(root,target){
  const rel=path.relative(path.resolve(root),path.resolve(target));
  return rel===''||(!rel.startsWith(`..${path.sep}`)&&rel!=='..'&&!path.isAbsolute(rel));
}

function extOf(name){
  const lower=String(name||'').toLowerCase();
  if(lower.endsWith('.tar.gz'))return '.tar.gz';
  return path.extname(lower);
}

function archiveKind(buffer,name=''){
  const ext=extOf(name);
  if(Buffer.isBuffer(buffer)&&buffer.length>=4){
    const sig4=buffer.readUInt32LE(0);
    if(ZIP_EXTENSIONS.has(ext)&&[0x04034b50,0x06054b50,0x08074b50].includes(sig4))return'ZIP';
    if((GZIP_EXTENSIONS.has(ext)||ext==='.tar.gz')&&buffer[0]===0x1f&&buffer[1]===0x8b)return'GZIP';
    if(TAR_EXTENSIONS.has(ext)&&isTar(buffer))return'TAR';
    if(buffer.length>=6&&buffer.subarray(0,6).equals(Buffer.from('377abcaf271c','hex')))return'7Z';
    if(buffer.subarray(0,7).equals(Buffer.from('526172211a0700','hex'))||buffer.subarray(0,8).equals(Buffer.from('526172211a070100','hex')))return'RAR';
  }
  return null;
}

function safeArchiveStem(name){
  const base=path.basename(String(name||'archive')).replace(/[^A-Za-z0-9._-]+/g,'_').replace(/^[.]+/,'').slice(0,120)||'archive';
  return `${base}.contents`;
}

function safeRelativeEntry(name){
  const raw=String(name||'').replace(/\\/g,'/');
  if(!raw||raw.includes('\0')||raw.startsWith('/')||raw.startsWith('\\')||/^[A-Za-z]:/.test(raw))return null;
  const parts=raw.split('/').filter((part)=>part&&part!=='.');
  if(!parts.length||parts.some((part)=>part==='..'))return null;
  const clean=parts.map((part)=>part.replace(/[<>:"|?*\x00-\x1f]/g,'_').replace(/[. ]+$/g,'').slice(0,160)||'_');
  return clean.join(path.sep);
}

function findEocd(buffer){
  const minimum=Math.max(0,buffer.length-0x10000-22);
  for(let offset=buffer.length-22;offset>=minimum;offset-=1){
    if(buffer.readUInt32LE(offset)===0x06054b50)return offset;
  }
  return-1;
}

function parseZipEntries(buffer,maxEntries=DEFAULT_LIMITS.maxEntries){
  if(!Buffer.isBuffer(buffer)||buffer.length<22)return null;
  const eocd=findEocd(buffer);if(eocd<0)return null;
  const disk=buffer.readUInt16LE(eocd+4),directoryDisk=buffer.readUInt16LE(eocd+6);
  const diskEntries=buffer.readUInt16LE(eocd+8),entryCount=buffer.readUInt16LE(eocd+10);
  const directorySize=buffer.readUInt32LE(eocd+12),directoryOffset=buffer.readUInt32LE(eocd+16);
  if(disk!==0||directoryDisk!==0||diskEntries!==entryCount)throw new Error('multi-disk ZIP is not supported');
  if(entryCount===0xffff||directorySize===0xffffffff||directoryOffset===0xffffffff)throw new Error('ZIP64 archive requires a dedicated extractor and is not auto-expanded');
  if(entryCount>maxEntries)throw new Error(`ZIP entry count ${entryCount} exceeds ${maxEntries}`);
  if(directoryOffset+directorySize>buffer.length)throw new Error('ZIP central directory is truncated');
  const entries=[];let offset=directoryOffset;
  for(let index=0;index<entryCount;index+=1){
    if(offset+46>buffer.length||buffer.readUInt32LE(offset)!==0x02014b50)throw new Error('ZIP central directory entry is invalid');
    const versionMadeBy=buffer.readUInt16LE(offset+4);
    const flags=buffer.readUInt16LE(offset+8),compression=buffer.readUInt16LE(offset+10);
    const crc32=buffer.readUInt32LE(offset+16),compressedSize=buffer.readUInt32LE(offset+20),uncompressedSize=buffer.readUInt32LE(offset+24);
    const fileNameLength=buffer.readUInt16LE(offset+28),extraLength=buffer.readUInt16LE(offset+30),commentLength=buffer.readUInt16LE(offset+32);
    const externalAttributes=buffer.readUInt32LE(offset+38),localHeaderOffset=buffer.readUInt32LE(offset+42);
    if([compressedSize,uncompressedSize,localHeaderOffset].includes(0xffffffff))throw new Error('ZIP64 entry is not auto-expanded');
    const nameStart=offset+46,nameEnd=nameStart+fileNameLength;
    if(nameEnd>buffer.length)throw new Error('ZIP filename is truncated');
    const name=buffer.subarray(nameStart,nameEnd).toString((flags&0x800)?'utf8':'utf8');
    const unixMode=(externalAttributes>>>16)&0xffff;
    const isSymlink=((versionMadeBy>>>8)===3)&&((unixMode&0o170000)===0o120000);
    entries.push({name,flags,compression,crc32,compressedSize,uncompressedSize,localHeaderOffset,isSymlink,externalAttributes});
    offset=nameEnd+extraLength+commentLength;
  }
  return{entries,entryCountDeclared:entryCount,directoryOffset,directorySize};
}

let CRC_TABLE=null;
function crcTable(){
  if(CRC_TABLE)return CRC_TABLE;
  CRC_TABLE=new Uint32Array(256);
  for(let n=0;n<256;n+=1){let c=n;for(let k=0;k<8;k+=1)c=(c&1)?(0xedb88320^(c>>>1)):(c>>>1);CRC_TABLE[n]=c>>>0;}
  return CRC_TABLE;
}
function crc32(buffer){
  let c=0xffffffff;const table=crcTable();
  for(const byte of buffer)c=table[(c^byte)&0xff]^(c>>>8);
  return(c^0xffffffff)>>>0;
}
function sha256(buffer){return crypto.createHash('sha256').update(buffer).digest('hex');}

function extractZipEntry(buffer,entry,limits){
  if(entry.flags&1)throw new Error('encrypted ZIP entry');
  if(entry.isSymlink)throw new Error('ZIP symlink entry');
  if(![0,8].includes(entry.compression))throw new Error(`unsupported ZIP compression ${entry.compression}`);
  if(entry.uncompressedSize<0||entry.uncompressedSize>limits.maxEntryBytes||entry.compressedSize>limits.maxArchiveBytes)throw new Error('ZIP entry exceeds size limit');
  if(entry.compressedSize>0&&entry.uncompressedSize>2*1024*1024&&(entry.uncompressedSize/entry.compressedSize)>limits.maxCompressionRatio)throw new Error('ZIP compression ratio exceeds bomb limit');
  const offset=entry.localHeaderOffset;
  if(offset+30>buffer.length||buffer.readUInt32LE(offset)!==0x04034b50)throw new Error('ZIP local header is invalid');
  const localFlags=buffer.readUInt16LE(offset+6),localCompression=buffer.readUInt16LE(offset+8);
  if((localFlags&1)||localCompression!==entry.compression)throw new Error('ZIP local header disagrees with central directory');
  const nameLength=buffer.readUInt16LE(offset+26),extraLength=buffer.readUInt16LE(offset+28);
  const start=offset+30+nameLength+extraLength,end=start+entry.compressedSize;
  if(start<0||end>buffer.length)throw new Error('ZIP entry data is truncated');
  const data=buffer.subarray(start,end);
  const output=entry.compression===0?Buffer.from(data):zlib.inflateRawSync(data,{maxOutputLength:limits.maxEntryBytes});
  if(output.length!==entry.uncompressedSize)throw new Error(`ZIP entry size mismatch (${output.length} != ${entry.uncompressedSize})`);
  if(crc32(output)!==entry.crc32)throw new Error('ZIP entry CRC32 mismatch');
  return output;
}

async function uniqueTarget(root,relative,used){
  let candidate=relative,index=1;
  const ext=path.extname(relative),stem=ext?relative.slice(0,-ext.length):relative;
  while(used.has(candidate.toLowerCase()))candidate=`${stem}__dup${index++}${ext}`;
  used.add(candidate.toLowerCase());
  const target=path.resolve(root,candidate);
  if(!inside(root,target))throw new Error('archive entry escapes extraction root');
  await fs.mkdir(path.dirname(target),{recursive:true});
  return{target,relative:candidate};
}

function skippedRecord(state,ctx,entry,reason){
  state.skipped.push({archive:ctx.label,entry:String(entry||''),depth:ctx.depth,reason:String(reason||'skipped').slice(0,240)});
}

async function writeExtracted(state,ctx,relative,buffer,meta={}){
  if(state.files.length>=state.limits.maxEntries)throw new Error(`expanded file count exceeds ${state.limits.maxEntries}`);
  if(buffer.length>state.limits.maxEntryBytes)throw new Error(`expanded entry exceeds ${state.limits.maxEntryBytes} bytes`);
  if(state.totalBytes+buffer.length>state.limits.maxExpandedBytes)throw new Error(`expanded bytes exceed ${state.limits.maxExpandedBytes}`);
  const slot=await uniqueTarget(ctx.outputRoot,relative,ctx.used);
  await fs.writeFile(slot.target,buffer,{flag:'wx'});
  state.totalBytes+=buffer.length;
  const record={path:path.relative(state.sessionRoot,slot.target),size:buffer.length,sha256:sha256(buffer),archive:ctx.label,entry:meta.entry||relative,depth:ctx.depth,kind:meta.kind||'entry'};
  state.files.push(record);
  return{...slot,record};
}

async function expandBuffer(buffer,name,outputRoot,state,depth,lineage){
  if(depth>state.limits.maxDepth)return;
  const kind=archiveKind(buffer,name);
  if(!kind)return;
  const ctx={label:lineage.join(' > '),outputRoot,depth,used:new Set()};
  if(kind==='7Z'||kind==='RAR'){
    state.unsupported.push({archive:ctx.label,kind,depth,reason:'recognized but no in-process safe extractor is bundled'});
    return;
  }
  const archiveRecord={archive:ctx.label,kind,depth,entries:0,extracted:0,skipped:0};
  state.archives.push(archiveRecord);
  await fs.mkdir(outputRoot,{recursive:true});

  if(kind==='ZIP'){
    const parsed=parseZipEntries(buffer,state.limits.maxEntries-state.files.length);
    if(!parsed)throw new Error('invalid ZIP archive');
    archiveRecord.entries=parsed.entries.length;
    for(const entry of parsed.entries){
      if(/[\\/]$/.test(entry.name))continue;
      const safe=safeRelativeEntry(entry.name);
      if(!safe){archiveRecord.skipped+=1;skippedRecord(state,ctx,entry.name,'unsafe path');continue;}
      try{
        const content=extractZipEntry(buffer,entry,state.limits);
        const written=await writeExtracted(state,ctx,safe,content,{entry:entry.name,kind:'zip-entry'});
        archiveRecord.extracted+=1;
        const childKind=archiveKind(content,entry.name);
        if(childKind&&depth<state.limits.maxDepth){
          const childRoot=`${written.target}.contents`;
          await expandBuffer(content,entry.name,childRoot,state,depth+1,[...lineage,entry.name]);
        }
      }catch(error){archiveRecord.skipped+=1;skippedRecord(state,ctx,entry.name,error?.message||error);}
    }
    return;
  }

  if(kind==='GZIP'){
    const remaining=Math.max(1,state.limits.maxExpandedBytes-state.totalBytes);
    const maxOutput=Math.min(remaining,state.limits.maxEntryBytes*4);
    let content;
    try{content=zlib.gunzipSync(buffer,{maxOutputLength:maxOutput});}
    catch(error){archiveRecord.skipped+=1;skippedRecord(state,ctx,name,error?.message||error);return;}
    const innerName=String(name||'archive.gz').replace(/\.(?:tgz|gz)$/i,(m)=>m.toLowerCase()==='.tgz'?'.tar':'')||'decompressed.bin';
    if(isTar(content)){
      archiveRecord.entries=1;
      await expandBuffer(content,innerName.endsWith('.tar')?innerName:`${innerName}.tar`,outputRoot,state,depth,lineage);
      archiveRecord.extracted=1;
      return;
    }
    archiveRecord.entries=1;
    try{await writeExtracted(state,ctx,safeRelativeEntry(path.basename(innerName))||'decompressed.bin',content,{entry:path.basename(innerName),kind:'gzip-output'});archiveRecord.extracted=1;}
    catch(error){archiveRecord.skipped=1;skippedRecord(state,ctx,name,error?.message||error);}
    return;
  }

  if(kind==='TAR'){
    const parsed=parseTar(buffer,{maxEntries:Math.min(4096,state.limits.maxEntries-state.files.length),maxEntryBytes:state.limits.maxEntryBytes});
    if(!parsed)throw new Error('invalid TAR archive');
    archiveRecord.entries=parsed.entries.length;
    for(const entry of parsed.entries){
      if(!entry.regular||!entry.exportable){archiveRecord.skipped+=1;skippedRecord(state,ctx,entry.name,'non-regular or oversized TAR entry');continue;}
      const safe=safeRelativeEntry(entry.name);
      if(!safe){archiveRecord.skipped+=1;skippedRecord(state,ctx,entry.name,'unsafe path');continue;}
      try{
        const content=extractTarEntry(buffer,entry,state.limits.maxEntryBytes);
        if(!content)throw new Error('TAR entry extraction failed');
        const written=await writeExtracted(state,ctx,safe,content,{entry:entry.name,kind:'tar-entry'});
        archiveRecord.extracted+=1;
        const childKind=archiveKind(content,entry.name);
        if(childKind&&depth<state.limits.maxDepth)await expandBuffer(content,entry.name,`${written.target}.contents`,state,depth+1,[...lineage,entry.name]);
      }catch(error){archiveRecord.skipped+=1;skippedRecord(state,ctx,entry.name,error?.message||error);}
    }
  }
}

function normalizedLimits(options={}){
  const limits={...DEFAULT_LIMITS};
  for(const key of Object.keys(limits))if(Number.isFinite(Number(options[key]))&&Number(options[key])>0)limits[key]=Math.floor(Number(options[key]));
  limits.maxEntries=Math.max(1,Math.min(limits.maxEntries,6000));
  limits.maxDepth=Math.max(0,Math.min(limits.maxDepth,5));
  return limits;
}

async function expandChallengeArchive(sourcePath,sessionRoot,options={}){
  const limits=normalizedLimits(options);
  const source=path.resolve(String(sourcePath||'')),root=path.resolve(String(sessionRoot||''));
  const stat=await fs.stat(source);
  if(!stat.isFile())throw new Error('archive source is not a regular file');
  if(stat.size<=0||stat.size>limits.maxArchiveBytes)throw new Error(`archive source size ${stat.size} exceeds auto-ingest limit ${limits.maxArchiveBytes}`);
  const buffer=await fs.readFile(source);
  const kind=archiveKind(buffer,path.basename(source));
  if(!kind)return{applicable:false,source:path.basename(source),kind:null,archives:[],files:[],skipped:[],unsupported:[],totalBytes:0,limits};
  const state={sessionRoot:root,limits,totalBytes:0,files:[],archives:[],skipped:[],unsupported:[]};
  const outputRoot=path.join(root,'__expanded__',safeArchiveStem(path.basename(source)));
  await expandBuffer(buffer,path.basename(source),outputRoot,state,0,[path.basename(source)]);
  return{applicable:true,source:path.basename(source),kind,outputRoot:path.relative(root,outputRoot),archives:state.archives,files:state.files,skipped:state.skipped,unsupported:state.unsupported,totalBytes:state.totalBytes,limits};
}

module.exports={DEFAULT_LIMITS,archiveKind,safeRelativeEntry,parseZipEntries,extractZipEntry,crc32,expandChallengeArchive};