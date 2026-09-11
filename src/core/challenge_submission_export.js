'use strict';

const path=require('path');

const OUTPUT_DIR='__newcyber_output__';
const SUBMISSION_PREFIX='newcyber_submission_';
function resolveSubmissionArtifact(rootPath,relativePath){
  const root=path.resolve(String(rootPath||''));const rel=String(relativePath||'');
  if(!root||!rel||path.isAbsolute(rel)||rel.includes('\0'))return null;
  const normalized=rel.replace(/\\/g,'/');
  if(!normalized.startsWith(`${OUTPUT_DIR}/`))return null;
  const basename=path.basename(normalized);
  if(!basename.startsWith(SUBMISSION_PREFIX))return null;
  const outputRoot=path.resolve(root,OUTPUT_DIR);const target=path.resolve(root,normalized);
  const prefix=outputRoot.endsWith(path.sep)?outputRoot:`${outputRoot}${path.sep}`;
  if(target===outputRoot||!target.startsWith(prefix))return null;
  return target;
}
function safeSuggestedName(value,fallback='newcyber_submission.txt'){
  const raw=path.basename(String(value||fallback)).replace(/[<>:"/\\|?*\x00-\x1f]/g,'_').replace(/[. ]+$/g,'').trim();
  const name=(raw||fallback).slice(0,180);
  return name.startsWith(SUBMISSION_PREFIX)?name:`${SUBMISSION_PREFIX}${name}`;
}

module.exports={OUTPUT_DIR,SUBMISSION_PREFIX,resolveSubmissionArtifact,safeSuggestedName};
