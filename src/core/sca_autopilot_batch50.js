'use strict';

// Batch50 remains the stable compatibility import used by historical Electron,
// Workspace and HF/SCA callers. Batch55 wraps the frozen Batch50 implementation
// with source-priority, strict quality routing and route telemetry, so existing
// production imports receive the stronger path without per-caller rewiring.
module.exports=require('./sca_autopilot_batch55');
