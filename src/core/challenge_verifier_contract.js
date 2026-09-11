'use strict';

// Compatibility entrypoint: Batch88 introduced challenge_verifier_contract_v3 structured-candidate closure.
// Batch91 extends it with the bounded static return-predicate interpreter in challenge_verifier_contract_v4.
// Historical marker retained for regression/import audits: challenge_verifier_contract_v3.
module.exports=require('./challenge_verifier_contract_v4');
