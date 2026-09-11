const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('newcyber', {
  chooseWorkspace: () => ipcRenderer.invoke('workspace:choose'),
  scanWorkspace: (rootPath) => ipcRenderer.invoke('workspace:scan', rootPath),
  inspectFile: (rootPath, relativePath) => ipcRenderer.invoke('workspace:inspect', rootPath, relativePath),
  chooseChallengeFiles: () => ipcRenderer.invoke('challenge:choose-files'),
  analyzeDroppedChallenge: (files) => {
    const paths = [...(files || [])].map((file) => webUtils.getPathForFile(file)).filter(Boolean);
    return ipcRenderer.invoke('challenge:analyze-dropped', paths);
  },
  addChallengeFiles: (rootPath) => ipcRenderer.invoke('challenge:add-files', rootPath),
  addDroppedChallengeFiles: (rootPath, files) => {
    const paths = [...(files || [])].map((file) => webUtils.getPathForFile(file)).filter(Boolean);
    return ipcRenderer.invoke('challenge:add-dropped', rootPath, paths);
  },
  rescanChallenge: (rootPath) => ipcRenderer.invoke('challenge:rescan', rootPath),
  inspectChallengeFile: (rootPath, relativePath) => ipcRenderer.invoke('challenge:inspect', rootPath, relativePath),
  revealArtifact: (rootPath, relativePath) => ipcRenderer.invoke('artifact:reveal-path', rootPath, relativePath),
  exportSubmissionArtifact: (rootPath, relativePath, suggestedName) => ipcRenderer.invoke('artifact:export-submission', rootPath, relativePath, suggestedName),
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
  chooseAndAnalyzePowerSideChannel: () => ipcRenderer.invoke('ai:sca-choose-analyze'),
  chooseAndRunScaAutopilot: () => ipcRenderer.invoke('ai:sca-autopilot-choose'),
  continueScaAutopilotWithConversion: (payload) => ipcRenderer.invoke('ai:sca-autopilot-convert-resume', payload || {}),
  analyzeDroppedPowerSideChannel: (files) => {
    const paths = [...(files || [])].map((file) => webUtils.getPathForFile(file)).filter(Boolean);
    return ipcRenderer.invoke('ai:sca-analyze-dropped', paths);
  },
  extractPowerSideChannelWindows: (payload) => ipcRenderer.invoke('ai:sca-extract-windows', payload),
  fitScaLeakageProfile: (payload) => ipcRenderer.invoke('ai:sca-fit-leakage-profile', payload),
  recoverScaProbeCandidates: (payload) => ipcRenderer.invoke('ai:sca-recover-probe', payload),
  getLocalMlRuntimeStatus: () => ipcRenderer.invoke('ai:local-ml-status'),
  chooseLocalMlRuntimeBundle: () => ipcRenderer.invoke('ai:local-ml-select-runtime'),
  getTrustedHfConverterStatus: () => ipcRenderer.invoke('ai:hf-converter-status'),
  chooseTrustedHfConverter: () => ipcRenderer.invoke('ai:hf-converter-select'),
  chooseHfOnnxExportPlan: () => ipcRenderer.invoke('ai:hf-onnx-choose-plan'),
  saveHfOnnxExportPlan: (payload) => ipcRenderer.invoke('ai:hf-onnx-save-plan', payload || {}),
  executeTrustedHfOnnxConversion: (payload) => ipcRenderer.invoke('ai:hf-onnx-execute', payload || {}),
  chooseAndInspectOnnxModel: (provider) => ipcRenderer.invoke('ai:onnx-choose-inspect', provider || 'cpu'),
  inspectDroppedOnnxModel: (file, provider) => {
    const filePath = file ? webUtils.getPathForFile(file) : '';
    return ipcRenderer.invoke('ai:onnx-inspect-dropped', filePath, provider || 'cpu');
  },
  runOnnxModel: (payload) => ipcRenderer.invoke('ai:onnx-run', payload),
  runTransformerOracle: (payload) => ipcRenderer.invoke('ai:transformer-run', payload),
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