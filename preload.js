const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('newcyber', {
  chooseWorkspace: () => ipcRenderer.invoke('workspace:choose'),
  scanWorkspace: (rootPath) => ipcRenderer.invoke('workspace:scan', rootPath),
  inspectFile: (rootPath, relativePath) => ipcRenderer.invoke('workspace:inspect', rootPath, relativePath),
  getPocIndexStatus: () => ipcRenderer.invoke('poc:index-status'),
  importPocIndex: () => ipcRenderer.invoke('poc:index-import'),
  getAdvisoryIndexStatus: () => ipcRenderer.invoke('advisory:index-status'),
  importAdvisoryIndex: () => ipcRenderer.invoke('advisory:index-import'),
  saveReport: (payload) => ipcRenderer.invoke('report:save', payload),
  saveArtifact: (artifact) => ipcRenderer.invoke('artifact:save', artifact),
  exportAutopilotBundle: (payload) => ipcRenderer.invoke('autopilot:export-bundle', payload),
  chooseAndAnalyzeFirmware: () => ipcRenderer.invoke('firmware:choose-analyze'),
  analyzeDroppedFirmware: (file) => {
    const filePath = file ? webUtils.getPathForFile(file) : '';
    return ipcRenderer.invoke('firmware:analyze-dropped', filePath);
  },
  chooseAndAnalyzeBinary: () => ipcRenderer.invoke('binary:choose-analyze'),
  analyzeDroppedBinary: (file) => {
    const filePath = file ? webUtils.getPathForFile(file) : '';
    return ipcRenderer.invoke('binary:analyze-dropped', filePath);
  },
  chooseAndAnalyzeIdaSnapshot: () => ipcRenderer.invoke('ida:choose-analyze'),
  analyzeDroppedIdaSnapshot: (file) => {
    const filePath = file ? webUtils.getPathForFile(file) : '';
    return ipcRenderer.invoke('ida:analyze-dropped', filePath);
  },
  exportFirmwareRecovered: (filePath) => ipcRenderer.invoke('firmware:export-recovered', filePath),
  extractFirmwareWithBinwalk: (filePath) => ipcRenderer.invoke('firmware:extract-binwalk', filePath),
  getAiBackendStatus: () => ipcRenderer.invoke('ai:backend-status'),
  chooseAndScanAiModel: () => ipcRenderer.invoke('ai:model-choose-scan'),
  rescanAiModel: (filePath) => ipcRenderer.invoke('ai:model-rescan', filePath),
  runTool: (tool, payload) => ipcRenderer.invoke('toolbox:run', tool, payload),
  getWindowState: () => ipcRenderer.invoke('window:state'),
  toggleAlwaysOnTop: () => ipcRenderer.invoke('window:toggle-always-on-top'),
  setTaskProgress: (value) => ipcRenderer.invoke('window:task-progress', value),
  onWindowState: (listener) => {
    if (typeof listener !== 'function') return () => {};
    const handler = (_event, state) => listener(state);
    ipcRenderer.on('window:state-changed', handler);
    return () => ipcRenderer.removeListener('window:state-changed', handler);
  }
});