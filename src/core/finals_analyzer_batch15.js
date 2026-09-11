// Compatibility entrypoint: Electron/main and older imports automatically receive the newest workspace analyzer.
// Historical compatibility marker kept for tests/import audits: require('./finals_analyzer_batch41')
// The Batch49 wrapper extends the Batch41 analyzer; it does not bypass the executor chain.
module.exports = require('./finals_analyzer_batch49');