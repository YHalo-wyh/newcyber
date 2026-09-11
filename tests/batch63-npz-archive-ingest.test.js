'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const {archiveKind,crc32,expandChallengeArchive}=require('../src/core/challenge_archive_ingest');

function storedZip(entries){
  const locals=[];const centrals=[];let offset=0;
  for(const entry of entries){
    const name=Buffer.from(entry.name,'utf8'),data=Buffer.isBuffer(entry.data)?entry.data:Buffer.from(entry.data||''),crc=crc32(data);
    const local=Buffer.alloc(30+name.length+data.length);local.writeUInt32LE(0x04034b50,0);local.writeUInt16LE(20,4);local.writeUInt16LE(0x800,6);local.writeUInt16LE(0,8);local.writeUInt32LE(crc,14);local.writeUInt32LE(data.length,18);local.writeUInt32LE(data.length,22);local.writeUInt16LE(name.length,26);name.copy(local,30);data.copy(local,30+name.length);locals.push(local);
    const central=Buffer.alloc(46+name.length);central.writeUInt32LE(0x02014b50,0);central.writeUInt16LE((3<<8)|20,4);central.writeUInt16LE(20,6);central.writeUInt16LE(0x800,8);central.writeUInt16LE(0,10);central.writeUInt32LE(crc,16);central.writeUInt32LE(data.length,20);central.writeUInt32LE(data.length,24);central.writeUInt16LE(name.length,28);central.writeUInt32LE(0o100644*0x10000,38);central.writeUInt32LE(offset,42);name.copy(central,46);centrals.push(central);offset+=local.length;
  }
  const centralSize=centrals.reduce((sum,item)=>sum+item.length,0),eocd=Buffer.alloc(22);eocd.writeUInt32LE(0x06054b50,0);eocd.writeUInt16LE(entries.length,8);eocd.writeUInt16LE(entries.length,10);eocd.writeUInt32LE(centralSize,12);eocd.writeUInt32LE(offset,16);
  return Buffer.concat([...locals,...centrals,eocd]);
}
function npyFloat32(){
  let header="{'descr': '<f4', 'fortran_order': False, 'shape': (2,), }";const base=10+Buffer.byteLength(header,'latin1')+1,padded=Math.ceil(base/64)*64;header=`${header}${' '.repeat(padded-base)}\n`;const magic=Buffer.from([0x93,0x4e,0x55,0x4d,0x50,0x59,0x01,0x00]),len=Buffer.alloc(2);len.writeUInt16LE(Buffer.byteLength(header,'latin1'),0);const payload=Buffer.alloc(8);payload.writeFloatLE(1,0);payload.writeFloatLE(2,4);return Buffer.concat([magic,len,Buffer.from(header,'latin1'),payload]);
}

test('NPZ extension is recognized as safe ZIP container',()=>{const archive=storedZip([{name:'arr_0.npy',data:npyFloat32()}]);assert.equal(archiveKind(archive,'samples.npz'),'ZIP');});

test('top-level NPZ expands NPY members without Python or allow_pickle',async(t)=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-npz-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));const source=path.join(root,'samples.npz');await fs.writeFile(source,storedZip([{name:'arr_0.npy',data:npyFloat32()}]));
  const result=await expandChallengeArchive(source,root,{maxEntries:16,maxEntryBytes:1024*1024,maxExpandedBytes:4*1024*1024,maxDepth:2});assert.equal(result.applicable,true);assert.equal(result.kind,'ZIP');assert.equal(result.files.length,1);assert.ok(result.files[0].path.endsWith(path.join('samples.npz.contents','arr_0.npy')));const extracted=await fs.readFile(path.join(root,result.files[0].path));assert.equal(extracted.subarray(0,6).toString('hex'),'934e554d5059');
});

test('nested NPZ inside challenge ZIP is recursively expanded',async(t)=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'newcyber-npz-nested-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));const nested=storedZip([{name:'target.npy',data:npyFloat32()}]);const source=path.join(root,'challenge.zip');await fs.writeFile(source,storedZip([{name:'data/samples.npz',data:nested}]));
  const result=await expandChallengeArchive(source,root,{maxEntries:32,maxEntryBytes:1024*1024,maxExpandedBytes:8*1024*1024,maxDepth:3});assert.ok(result.files.some((item)=>item.path.endsWith(path.join('samples.npz.contents','target.npy'))));
});
