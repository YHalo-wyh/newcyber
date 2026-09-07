const toolbox = require('./toolbox');
const { analyzeCanAdvanced, decodeUdsAdvanced } = require('./vehicle');

function runTool(tool, payload = {}) {
  if (tool === 'can-analyze') return analyzeCanAdvanced(payload.input);
  if (tool === 'uds-decode') return decodeUdsAdvanced(payload.input);
  return toolbox.runTool(tool, payload);
}

module.exports = { runTool };
