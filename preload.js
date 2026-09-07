const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('newcyber', {
  chooseWorkspace: () => ipcRenderer.invoke('workspace:choose'),
  scanWorkspace: (rootPath) => ipcRenderer.invoke('workspace:scan', rootPath),
  inspectFile: (rootPath, relativePath) => ipcRenderer.invoke('workspace:inspect', rootPath, relativePath),
  saveReport: (payload) => ipcRenderer.invoke('report:save', payload),
  runTool: (tool, payload) => ipcRenderer.invoke('toolbox:run', tool, payload)
});
