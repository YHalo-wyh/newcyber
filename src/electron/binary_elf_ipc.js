'use strict';

const { BrowserWindow, dialog, ipcMain } = require('electron');
const fs = require('fs/promises');
const path = require('path');
const { analyzeElfBinary, MAX_ELF_BYTES } = require('../core/binary_elf_loader');
const { scanX86_64DataRefs } = require('../core/x86_64_data_refs');

function activeWindow() {
  return BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0] || null;
}

function addStandaloneCodeRefs(analysis, buffer) {
  if (analysis?.source?.elf?.bits !== 64 || analysis?.source?.elf?.machine !== 'x86-64') return analysis;
  const scan = scanX86_64DataRefs(buffer, analysis.sections || [], analysis.objects || [], [], { littleEndian:analysis.source.elf.endian !== 'big' });
  if (!scan.relations.length) {
    analysis.summary = { ...(analysis.summary || {}), standaloneCodeRefs:0, standaloneCodeBytes:scan.scannedBytes };
    analysis.notes = [...(analysis.notes || []), 'Standalone x86-64 code-ref scanner 未找到指向已恢复数据对象的直接 RIP-relative 引用；这不等于程序没有数据引用。'];
    return analysis;
  }
  const relationKeys = new Set((analysis.relations || []).map((relation) => `${relation.source}|${relation.target}|${relation.type}|${relation.location || ''}`));
  for (const relation of scan.relations) {
    const key = `${relation.source}|${relation.target}|${relation.type}|${relation.location || ''}`;
    if (relationKeys.has(key)) continue;
    relation.id = `rel_${(analysis.relations?.length || 0)+1}`;
    analysis.relations.push(relation); relationKeys.add(key);
  }
  analysis.operations = [...(analysis.operations || []), ...scan.operations];
  const important = analysis.relations.filter((relation) => ['POINTS_TO','LENGTH_OF','REFERENCES','RELOCATES_TO','READS','COMPARES_WITH','TAKES_ADDRESS'].includes(relation.type));
  analysis.summary = {
    ...(analysis.summary || {}),
    operations:analysis.operations.length,
    relations:analysis.relations.length,
    importantRelations:important.length,
    standaloneCodeRefs:scan.relations.length,
    standaloneCodeBytes:scan.scannedBytes
  };
  analysis.source.parser = `${analysis.source.parser}+x86-ripref-v0.1`;
  analysis.notes = [
    ...(analysis.notes || []),
    `Standalone x86-64 模式从可执行 section 中恢复 ${scan.relations.length} 条直接 RIP-relative code→data 关系；仅接受目标落入已知数据对象的保守模式。`,
    '该扫描器不是完整反汇编器：它覆盖 LEA/MOV/MOVZX/XOR/ADD/SUB/CMP 的直接 RIP-relative 数据引用，不推断复杂控制流或跨寄存器别名。'
  ];
  return analysis;
}

async function analyzeElfPath(filePath) {
  const resolved = path.resolve(String(filePath || ''));
  if (!resolved || resolved === path.parse(resolved).root) throw new Error('未获得有效 ELF 文件路径');
  const stat = await fs.stat(resolved);
  if (!stat.isFile()) throw new Error('拖入对象不是文件');
  if (stat.size <= 0) throw new Error('ELF 文件为空');
  if (stat.size > MAX_ELF_BYTES) throw new Error(`ELF 文件超过 ${MAX_ELF_BYTES} bytes 分析上限`);
  const handle = await fs.open(resolved, 'r');
  try {
    const magic = Buffer.alloc(4);
    const { bytesRead } = await handle.read(magic, 0, 4, 0);
    if (bytesRead !== 4 || !(magic[0] === 0x7f && magic[1] === 0x45 && magic[2] === 0x4c && magic[3] === 0x46)) throw new Error('选择的文件不是 ELF（Magic 不匹配）');
  } finally { await handle.close(); }
  const buffer = await fs.readFile(resolved);
  const analysis = addStandaloneCodeRefs(analyzeElfBinary(buffer, path.basename(resolved)), buffer);
  return { filePath:resolved, fileName:path.basename(resolved), size:stat.size, analysis };
}

function registerBinaryElfIpc() {
  if (ipcMain.listenerCount('binary:choose-analyze') || ipcMain.listenerCount('binary:analyze-dropped')) return;
  ipcMain.handle('binary:choose-analyze', async () => {
    const result = await dialog.showOpenDialog(activeWindow(), {
      title:'选择 ELF 二进制', properties:['openFile'],
      filters:[{ name:'ELF / Linux binary', extensions:['elf','bin','out','so'] },{ name:'All files', extensions:['*'] }]
    });
    if (result.canceled || !result.filePaths[0]) return null;
    return analyzeElfPath(result.filePaths[0]);
  });
  ipcMain.handle('binary:analyze-dropped', async (_event, filePath) => analyzeElfPath(filePath));
}

module.exports = { registerBinaryElfIpc, analyzeElfPath, addStandaloneCodeRefs };