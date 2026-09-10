'use strict';

// Compatibility entrypoint. Batch42 grouped math remains preserved in
// `sca_autopilot_grouped_core`; Batch46 keeps provenance-aware label recovery;
// production callers now receive Batch50's quality-first grouped feature,
// calibrated-probe and unknown-prefix oracle closure before the older fallback.
module.exports=require('./sca_autopilot_batch50');
