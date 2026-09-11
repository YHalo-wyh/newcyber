'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const fsp=require('fs/promises');
const os=require('os');
const path=require('path');
const zlib=require('zlib');
const {crc32,safeRelativeEntry,parseZipEntries,extractZipEntry,expandChallengeArchive}=require('../src/core/challenge_archive_ingest');

function storedZip(entries){
  const locals=[];const centrals=[];let offset=0;
  for(const entry of entries){
    const name=Buffer.from(entry.name,'utf8');const data=Buffer.isBuffer(entry.data)?entry.data:Buffer.from(String(entry.data||''));const crc=crc32(data);
    const local=Buffer.alloc(30+name.length+data.length);
    local.writeUInt32LE(0x04034b50,0);local.writeUInt16LE(20,4);local.writeUInt16LE(0x800,6);local.writeUInt16LE(0,8);
    local.writeUInt32LE(crc,14);local.writeUInt32LE(data.length,18);local.writeUInt32LE(data.length,22);local.writeUInt16LE(name.length,26);local.writeUInt16LE(0,28);
    name.copy(local,30);data.copy(local,30+name.length);locals.push(local);
    const central=Buffer.alloc(46+name.length);
    central.writeUInt32LE(0x02014b50,0);central.writeUInt16LE((3<<8)|20,4);central.writeUInt16LE(20,6);central.writeUInt16LE(0x800,8);central.writeUInt16LE(0,10);
    central.writeUInt32LE(crc,16);central.writeUInt32LE(data.length,20);central.writeUInt32LE(data.length,24);central.writeUInt16LE(name.length,28);central.writeUInt16LE(0,30);central.writeUInt16LE(0,32);central.writeUInt16LE(0,34);central.writeUInt16LE(0,36);central.writeUInt32LE(0o100644<<16,38);central.writeUInt32LE(offset,42);name.copy(central,46);centrals.push(central);
    offset+=local.length;
  }
  const centralOffset=offset;const centralSize=centrals.reduce((sum,item)=>sum+item.length,0);
  const eocd=Buffer.alloc(22);eocd.writeUInt32LE(0x06054b50,0);eocd.writeUInt16LE(0,4);eocd.writeUInt16LE(0,6);eocd.writeUInt16LE(entries.length,8);eocd.writeUInt16LE(entries.length,10);eocd.writeUInt32LE(centralSize,12);eocd.writeUInt32LE(centralOffset,16);eocd.writeUInt16LE(0,20);
  return Buffer.concat([...locals,...centrals,eocd]);
}

function tarHeader(name,size){
  const header=Buffer.alloc(512,0);Buffer.from(name).copy(header,0,0,100);Buffer.from('0000644\0').copy(header,100);Buffer.from('0000000\0').copy(header,108);Buffer.from('0000000\0').copy(header,116);
  const sizeText=size.toString(8).padStart(11,'0')+'\0';Buffer.from(sizeText).copy(header,124);Buffer.from('00000000000\0').copy(header,136);
  Buffer.from('        ').copy(header,148);header[156]='0'.charCodeAt(0);Buffer.from('ustar\0').copy(header,257);Buffer.from('00').copy(header,263);
  let sum=0;for(const byte of header)sum+=byte;Buffer.from(sum.toString(8).padStart(6,'0')+'\0 ').copy(header,148);return header;
}
function tar(entries){
  const parts=[];for(const entry of entries){const data=Buffer.from(String(entry.data||''));parts.push(tarHeader(entry.name,data.length),data,Buffer.alloc((512-(data.length%512))%512));}parts.push(Buffer.alloc(1024));return Buffer.concat(parts);
}

test('archive path guard rejects traversal and absolute paths',()=>{
  assert.equal(safeRelativeEntry('../evil.txt'),null);
  assert.equal(safeRelativeEntry('/tmp/evil.txt'),null);
  assert.equal(safeRelativeEntry('C:\\evil.txt'),null);
  assert.ok(safeRelativeEntry('src/app.py').endsWith(path.join('src','app.py')));
});

test('ZIP parser validates stored entry CRC and contents',()=>{
  const zip=storedZip([{name:'hello.txt',data:'hello'}]);
  const parsed=parseZipEntries(zip);assert.equal(parsed.entries.length,1);
  assert.equal(extractZipEntry(zip,parsed.entries[0],{maxEntryBytes:1024,maxArchiveBytes:4096,maxCompressionRatio:20}).toString(),'hello');
});

test('challenge ZIP is expanded recursively while traversal entries are skipped',async(t)=>{
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-archive-test-'));t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const nested=storedZip([{name:'config.json',data:'{"classes":10}'}]);
  const archive=storedZip([{name:'src/app.py',data:'print("challenge")'},{name:'../escape.txt',data:'nope'},{name:'nested.zip',data:nested}]);
  const source=path.join(root,'challenge.zip');await fsp.writeFile(source,archive);
  const result=await expandChallengeArchive(source,root,{maxExpandedBytes:8*1024*1024,maxEntryBytes:2*1024*1024,maxEntries:32,maxDepth:3});
  assert.equal(result.applicable,true);assert.equal(result.kind,'ZIP');
  assert.ok(result.files.some((item)=>item.path.endsWith(path.join('src','app.py'))));
  assert.ok(result.files.some((item)=>item.path.endsWith(path.join('nested.zip.contents','config.json'))));
  assert.ok(result.skipped.some((item)=>item.entry==='../escape.txt'&&item.reason==='unsafe path'));
  assert.equal(fs.existsSync(path.join(root,'escape.txt')),false);
});

test('tar.gz challenge archive expands regular files without external commands',async(t)=>{
  const root=await fsp.mkdtemp(path.join(os.tmpdir(),'newcyber-tgz-test-'));t.after(()=>fsp.rm(root,{recursive:true,force:true}));
  const archive=zlib.gzipSync(tar([{name:'README.md',data:'offline challenge'},{name:'data/hint.txt',data:'hint pair 1 -> 0'}]));
  const source=path.join(root,'bundle.tar.gz');await fsp.writeFile(source,archive);
  const result=await expandChallengeArchive(source,root,{maxExpandedBytes:8*1024*1024,maxEntryBytes:2*1024*1024,maxEntries:32,maxDepth:3});
  assert.equal(result.kind,'GZIP');
  assert.ok(result.files.some((item)=>item.path.endsWith('README.md')));
  assert.ok(result.files.some((item)=>item.path.endsWith(path.join('data','hint.txt'))));
});

test('challenge session IPC is wired to auto-expand archives',()=>{
  const source=fs.readFileSync(path.join(__dirname,'..','src','electron','challenge_session_ipc.js'),'utf8');
  assert.match(source,/expandChallengeArchive/);assert.match(source,/newcyber_ingest_manifest\.json/);assert.match(source,/archive-ingest/);
});
