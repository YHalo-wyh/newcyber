// Compatibility entrypoint: Electron/main and older imports automatically receive the newest workspace analyzer.
// Batch35 wraps Batch31 and preserves prior deterministic analyzers while adding bounded Power-SCA → Transformer autopilot.
module.exports = require('./finals_analyzer_batch35');