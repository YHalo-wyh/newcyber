const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('newcyber', {
  chooseWorkspace: () => ipcRenderer.invoke('workspace:choose'),
  scanWorkspace: (rootPath) => ipcRenderer.invoke('workspace:scan', rootPath),
  inspectFile: (rootPath, relativePath) => ipcRenderer.invoke('workspace:inspect', rootPath, relativePath),
  saveReport: (payload) => ipcRenderer.invoke('report:save', payload),
  saveArtifact: (artifact) => ipcRenderer.invoke('artifact:save', artifact),
  chooseAndAnalyzeFirmware: () => ipcRenderer.invoke('firmware:choose-analyze'),
  analyzeDroppedFirmware: (file) => {
    const filePath = file ? webUtils.getPathForFile(file) : '';
    return ipcRenderer.invoke('firmware:analyze-dropped', filePath);
  },
  exportFirmwareRecovered: (filePath) => ipcRenderer.invoke('firmware:export-recovered', filePath),
  extractFirmwareWithBinwalk: (filePath) => ipcRenderer.invoke('firmware:extract-binwalk', filePath),
  getAiBackendStatus: () => ipcRenderer.invoke('ai:backend-status'),
  chooseAndScanAiModel: () => ipcRenderer.invoke('ai:model-choose-scan'),
  rescanAiModel: (filePath) => ipcRenderer.invoke('ai:model-rescan', filePath),
  runTool: (tool, payload) => ipcRenderer.invoke('toolbox:run', tool, payload)
});
