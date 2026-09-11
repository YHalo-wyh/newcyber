'use strict';

const path=require('path');
const base=require('./challenge_submission_autopilot');

function highConfidenceTemplateName(file){
  const name=path.basename(String(file?.path||file?.file||'')).toLowerCase();
  return /(?:sample[_ -]?submission|submission|submit[_ -]?(?:format|template|sample|example)|answer[_ -]?template|prediction[_ -]?template|output[_ -]?template)/i.test(name);
}
function analyzeSubmissionBundle(files=[],analysis={}){
  const scoped=(Array.isArray(files)?files:[]).filter(highConfidenceTemplateName);
  if(!scoped.length)return{schema:'newcyber.challenge-submission-autopilot.v2',status:'not-detected',templates:[],candidates:base.resultCandidates(analysis).length,result:null,findings:[],next:null};
  const result=base.analyzeSubmissionBundle(scoped,analysis);
  return{...result,schema:'newcyber.challenge-submission-autopilot.v2'};
}

module.exports={...base,highConfidenceTemplateName,analyzeSubmissionBundle};
