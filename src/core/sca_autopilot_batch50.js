'use strict';

// Batch50 remains the stable compatibility import used by historical Electron,
// Workspace and HF/SCA callers. Batch56 first handles bundles with statically
// proven profiling prompt boundaries so per-position hidden states are captured
// contextually; everything else falls back to the verified Batch55 route.
module.exports=require('./sca_autopilot_batch56');
