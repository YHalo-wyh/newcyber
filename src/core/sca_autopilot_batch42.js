'use strict';

// Compatibility entrypoint. Batch42's grouped implementation is preserved in
// `sca_autopilot_grouped_core`; existing Workspace/HF/Electron imports keep this
// path and automatically receive the newer Batch46 provenance-aware dispatch.
module.exports=require('./sca_autopilot_batch46');
