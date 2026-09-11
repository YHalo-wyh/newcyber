'use strict';

// Compatibility entrypoint: callers that historically imported challenge_verifier_contract
// now receive the structured-candidate v3 closure. The frozen v2 implementation lives in
// challenge_verifier_contract_v2.js so v3 can extend it without a circular dependency.
module.exports=require('./challenge_verifier_contract_v3');
