'use strict';

// Batch50 remains the stable compatibility import used by historical Electron,
// Workspace and HF/SCA callers. Batch59 adds evidence-bound direct-drop role
// disambiguation before the Batch56 contextual-quality solver. The solver itself
// remains Batch56 and keeps all verified Batch55/50 fallback behavior.
module.exports=require('./sca_autopilot_batch59');
