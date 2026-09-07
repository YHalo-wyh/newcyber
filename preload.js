const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('newcyber', {
  chooseWorkspace: () => ipcRenderer.invoke('workspace:choose'),
  scanWorkspace: (rootPath) => ipcRenderer.invoke('workspace:scan', rootPath),
  inspectFile: (rootPath, relativePath) => ipcRenderer.invoke('workspace:inspect', rootPath, relativePath),
  saveReport: (payload) => ipcRenderer.invoke('report:save', payload),
  saveArtifact: (artifact) => ipcRenderer.invoke('artifact:save', artifact),
  chooseAndAnalyzeFirmware: () => ipcRenderer.invoke('firmware:choose-analyze'),
  extractFirmwareWithBinwalk: (filePath) => ipcRenderer.invoke('firmware:extract-binwalk', filePath),
  runTool: (tool, payload) => ipcRenderer.invoke('toolbox:run', tool, payload)
});
