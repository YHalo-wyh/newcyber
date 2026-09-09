'use strict';

const { BrowserWindow, dialog, ipcMain } = require('electron');
const fs = require('fs/promises');
const path = require('path');
const { analyzeElfBinary, MAX_ELF_BYTES } = require('../core/binary_elf_loader');
const { scanX86_64DataRefs } = require('../core/x86_64_data_refs');
const { scanX86_64ShortDataflow } = require('../core/x86_64_short_dataflow');

function activeWindow() {
  return BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0] || null;
}

function mergeRelations(analysis, rows) {
  const keys = new Set((analysis.relations || []).map((relation) => `${relation.source}|${relation.target}|${relation.type}|${relation.location || ''}`));
  let added = 0;
  for (const relation of rows || []) {
    const key = `${relation.source}|${relation.target}|${relation.type}|${relation.location || ''}`;
    if (keys.has(key)) continue;
    relation.id = `rel_${(analysis.relations?.length || 0)+1}`;
    analysis.relations.push(relation); keys.add(key); added += 1;
  }
  return added;
}

function mergeOperations(analysis, rows) {
  const keys = new Set((analysis.operations || []).map((operation) => `${operation.scope || ''}|${operation.op}|${operation.location || ''}|${operation.pseudo || ''}`));
  let added = 0;
  for (const operation of rows || []) {
    const key = `${operation.scope || ''}|${operation.op}|${operation.location || ''}|${operation.pseudo || ''}`;
    if (keys.has(key)) continue;
    analysis.operations.push(operation); keys.add(key); added += 1;
  }
  return added;
}

function addStandaloneCodeRefs(analysis, buffer) {
  if (analysis?.source?.elf?.bits !== 64 || analysis?.source?.elf?.machine !== 'x86-64') return analysis;
  const littleEndian = analysis.source.elf.endian !== 'big';
  const scan = scanX86_64DataRefs(buffer, analysis.sections || [], analysis.objects || [], [], { littleEndian });
  const flow = scanX86_64ShortDataflow(buffer, analysis.sections || [], analysis.objects || [], { littleEndian });
  const directAdded = mergeRelations(analysis, scan.relations);
  const flowRelationAdded = mergeRelations(analysis, flow.relations);
  const directOpsAdded = mergeOperations(analysis, scan.operations);
  const flowOpsAdded = mergeOperations(analysis, flow.operations);

  const recoverKeys = new Set((analysis.recoverableRelations || []).map((item) => `${item.operation}|${item.location}|${(item.objects || []).join('|')}`));
  let recoverableAdded = 0;
  for (const item of flow.recoverableRelations || []) {
    const key = `${item.operation}|${item.location}|${(item.objects || []).join('|')}`;
    if (recoverKeys.has(key)) continue;
    analysis.recoverableRelations.push(item); recoverKeys.add(key); recoverableAdded += 1;
  }

  const important = analysis.relations.filter((relation) => ['POINTS_TO','LENGTH_OF','REFERENCES','RELOCATES_TO','READS','COMPARES_WITH','TAKES_ADDRESS','XORS_WITH','INDEXES','INPUT_TO'].includes(relation.type));
  analysis.summary = {
    ...(analysis.summary || {}),
    operations:analysis.operations.length,
    relations:analysis.relations.length,
    importantRelations:important.length,
    recoverableRelations:analysis.recoverableRelations.length,
    standaloneCodeRefs:directAdded,
    standaloneCodeBytes:scan.scannedBytes,
    standaloneShortFlowOps:flowOpsAdded,
    standaloneShortFlowRelations:flowRelationAdded,
    standaloneRecoverable:recoverableAdded,
    standaloneShortFlowBytes:flow.scannedBytes
  };
  analysis.source.parser = `${analysis.source.parser}+x86-ripref-v0.1+x86-shortflow-v0.1`;
  analysis.notes = [
    ...(analysis.notes || []),
    directAdded
      ? `Standalone x86-64 模式从可执行 section 中恢复 ${directAdded} 条直接 RIP-relative code→data 关系。`
      : 'Standalone x86-64 direct-ref scanner 未找到指向已恢复数据对象的直接 RIP-relative 引用；这不等于程序没有数据引用。',
    flowOpsAdded
      ? `Batch28 short-flow 在局部直线代码中恢复 ${flowOpsAdded} 个 Operation、${flowRelationAdded} 条数据关系、${recoverableAdded} 条可逆关系；未知指令和控制流边界会清空寄存器状态。`
      : 'Batch28 short-flow 未形成可证明的局部表达式链；不会跨未知指令或控制流边界猜测寄存器状态。',
    'Standalone 路径仍不是完整反汇编/CFG/SSA：当前聚焦 x86-64 LEA/MOV/MOVZX、索引内存、XOR/ADD/SUB/AND/OR 与 CMP/Jcc 的短程确定性链。'
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
