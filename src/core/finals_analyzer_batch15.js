// Compatibility entrypoint: Electron/main and older imports automatically receive the newest workspace analyzer.
// Batch31 wraps and preserves finals_analyzer_batch22 behavior while adding bounded model-arithmetic auto recovery.
module.exports = require('./finals_analyzer_batch31');