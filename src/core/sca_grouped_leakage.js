'use strict';

const {pseudoinverseSolve}=require('./power_side_channel');
const {rankProbeCandidates}=require('./side_channel_probe');

const MAX_GROUPS=128;
const MAX_HIDDEN_PER_GROUP=256;
const MAX_GROUP_LEAKAGE_DIM=1024;
const MAX_PROFILE_TOKENS=16384;
const MAX_TARGET_TOKENS=4096;
const MAX_BATCH_VALUES=1_000_000;

function finiteMatrixRow(row,length,label){
  if(!Array.isArray(row)||row.length!==length||row.some((v)=>!Number.isFinite(Number(v))))throw new Error(`${label} 必须是 ${length} 维有限数值向量`);
  return row.map(Number);
}

function sourceGroupingEvidence(sourceText){
  const text=String(sourceText||'');
  const widths=[];const groups=[];const evidence=[];
  const push=(bucket,value,kind,match)=>{
    value=Number(value);if(!Number.isSafeInteger(value)||value<=0)return;
    bucket.push(value);evidence.push({kind,value,text:String(match||'').slice(0,180)});
  };
  for(const match of text.matchAll(/\b(?:HIDDEN_(?:GROUP|CHUNK|SLICE)_(?:WIDTH|SIZE|DIM)|GROUP_(?:WIDTH|SIZE)|CHUNK_(?:WIDTH|SIZE))\s*=\s*(\d+)\b/gi))push(widths,match[1],'hidden-width-constant',match[0]);
  for(const match of text.matchAll(/\b(?:ROWS_PER_TOKEN|GROUPS_PER_TOKEN|LEAKAGE_GROUPS|CHUNKS_PER_TOKEN|HIDDEN_GROUPS)\s*=\s*(\d+)\b/gi))push(groups,match[1],'groups-constant',match[0]);
  for(const match of text.matchAll(/(?:hidden|state)[^\n]{0,120}(?:reshape|view)\s*\([^\n)]*?,\s*(\d+)\s*\)/gi))push(widths,match[1],'hidden-reshape',match[0]);
  for(const match of text.matchAll(/range\s*\(\s*0\s*,\s*(?:hidden|hidden_size|dim|state)[^,\n]*,\s*(\d+)\s*\)/gi))push(widths,match[1],'hidden-range-step',match[0]);
  for(const match of text.matchAll(/(?:chunk|group|slice)[_\s]*(?:size|width|dim)\s*=\s*(\d+)/gi))push(widths,match[1],'hidden-group-assignment',match[0]);
  return {widths:[...new Set(widths)],groups:[...new Set(groups)],evidence};
}

function resolveGroupedLayout({manifest={},sourceText='',profileRows,profileTokens,hiddenDim,rowFeatureDim}){
  profileRows=Number(profileRows);profileTokens=Number(profileTokens);hiddenDim=Number(hiddenDim);rowFeatureDim=Number(rowFeatureDim);
  if(!Number.isSafeInteger(profileRows)||!Number.isSafeInteger(profileTokens)||profileRows<=0||profileTokens<=0||profileRows%profileTokens!==0)return {status:'not-applicable',code:'GROUP_ROW_RATIO_GAP',detail:`profile rows=${profileRows} 不能按 token rows=${profileTokens} 整分`};
  const ratio=profileRows/profileTokens;
  if(ratio<=1)return {status:'not-applicable',code:'NOT_GROUPED',detail:'profile trace 已是一行/token'};
  const block=manifest.groupedLeakage&&typeof manifest.groupedLeakage==='object'?manifest.groupedLeakage:{};
  const manifestGroups=Number(block.rowsPerToken??block.groupsPerToken??manifest.rowsPerToken??manifest.groupsPerToken??0);
  const manifestWidth=Number(block.hiddenPerGroup??block.hiddenGroupWidth??manifest.hiddenPerGroup??manifest.hiddenGroupWidth??0);
  const source=sourceGroupingEvidence(sourceText);
  let groups=null,width=null;const evidence=[];
  if(Number.isSafeInteger(manifestGroups)&&manifestGroups>1){groups=manifestGroups;evidence.push({kind:'manifest-groups',value:groups});}
  else if(source.groups.length===1){groups=source.groups[0];evidence.push(...source.evidence.filter((x)=>x.kind==='groups-constant'));}
  if(Number.isSafeInteger(manifestWidth)&&manifestWidth>0){width=manifestWidth;evidence.push({kind:'manifest-hidden-width',value:width});}
  else if(source.widths.length===1){width=source.widths[0];evidence.push(...source.evidence.filter((x)=>x.value===width));}
  if(groups==null&&width&&hiddenDim%width===0){groups=hiddenDim/width;evidence.push({kind:'derived-groups-from-hidden-width',value:groups});}
  if(width==null&&groups&&hiddenDim%groups===0){width=hiddenDim/groups;evidence.push({kind:'derived-hidden-width-from-groups',value:width});}
  if(groups==null||width==null){
    const derivedWidth=hiddenDim%ratio===0?hiddenDim/ratio:null;
    const sourceSupports=derivedWidth&&source.widths.includes(derivedWidth);
    if(sourceSupports){groups=ratio;width=derivedWidth;evidence.push({kind:'row-ratio',value:ratio},{kind:'source-hidden-width',value:width});}
  }
  if(!Number.isSafeInteger(groups)||groups<=1||groups>MAX_GROUPS)return {status:'not-applicable',code:'GROUP_LAYOUT_EVIDENCE_GAP',detail:'缺少 rowsPerToken / hidden group 的确定证据'};
  if(groups!==ratio)return {status:'gap',code:'GROUP_ROW_RATIO_GAP',detail:`group evidence=${groups}，但 profile rows/token=${ratio}`};
  if(!Number.isSafeInteger(width)||width<=0||width>MAX_HIDDEN_PER_GROUP||groups*width!==hiddenDim)return {status:'gap',code:'GROUP_HIDDEN_LAYOUT_GAP',detail:`groups=${groups} × hiddenPerGroup=${width} 与 hiddenDim=${hiddenDim} 不一致`};
  if(!Number.isSafeInteger(rowFeatureDim)||rowFeatureDim<=0||rowFeatureDim>MAX_GROUP_LEAKAGE_DIM)return {status:'gap',code:'GROUP_FEATURE_DIM_GAP',detail:`每 group leakage dim=${rowFeatureDim} 超过 ${MAX_GROUP_LEAKAGE_DIM} 或非法`};
  const featureEvidence=Number(block.rowFeatureDim??block.leakageDim??manifest.leakageDimPerGroup??0)===rowFeatureDim||Number(manifest.leakageDim??0)===rowFeatureDim||/\b(?:LEAKAGE_DIM|FEATURE_DIM)\s*=\s*\d+/i.test(sourceText);
  if(!Object.keys(block).length&&!featureEvidence&&!source.evidence.length)return {status:'not-applicable',code:'GROUP_FEATURE_RECIPE_GAP',detail:'只有行数比例，没有 source/manifest 证据证明这些行属于 token 分组 leakage'};
  return {status:'ok',mode:'token-groups',groupsPerToken:groups,hiddenPerGroup:width,hiddenDim,rowFeatureDim,profileTokens,profileRows,evidence:[{kind:'row-ratio',value:ratio},...evidence]};
}

function cholesky(matrix,tolerance=1e-12){
  const n=matrix.length;const L=Array.from({length:n},()=>Array(n).fill(0));
  for(let i=0;i<n;i+=1){for(let j=0;j<=i;j+=1){let sum=matrix[i][j];for(let k=0;k<j;k+=1)sum-=L[i][k]*L[j][k];if(i===j){if(!Number.isFinite(sum)||sum<=tolerance)return null;L[i][j]=Math.sqrt(sum);}else L[i][j]=sum/L[j][j];}}
  return L;
}

function solveCholeskyMany(L,rhs){
  const n=L.length,cols=rhs[0].length;const y=Array.from({length:n},()=>Array(cols).fill(0));
  for(let i=0;i<n;i+=1)for(let c=0;c<cols;c+=1){let v=rhs[i][c];for(let k=0;k<i;k++)v-=L[i][k]*y[k][c];y[i][c]=v/L[i][i];}
  const x=Array.from({length:n},()=>Array(cols).fill(0));
  for(let i=n-1;i>=0;i--)for(let c=0;c<cols;c+=1){let v=rhs[i][c];for(let k=0;k<i;k++)v-=L[i][k]*y[k][c];y[i][c]=v/L[i][i];}
  for(let i=n-1;i>=0;i--)for(let c=0;c<cols;c+=1){let v=y[i][c];for(let k=i+1;k<n;k++)v-=L[k][i]*x[k][c];x[i][c]=v/L[i][i];}
  return x;
}

function accumulator(hiddenDim,leakageDim){
  return {rows:0,hiddenDim,leakageDim,sumX:Array(hiddenDim).fill(0),sumY:Array(leakageDim).fill(0),sumXX:Array.from({length:hiddenDim},()=>Array(hiddenDim).fill(0)),sumXY:Array.from({length:hiddenDim},()=>Array(leakageDim).fill(0)),sumY2:0};
}

function updateAccumulator(acc,xInput,yInput){
  const x=finiteMatrixRow(xInput,acc.hiddenDim,'hidden group');const y=finiteMatrixRow(yInput,acc.leakageDim,'leakage group');acc.rows+=1;
  for(let i=0;i<acc.hiddenDim;i++){acc.sumX[i]+=x[i];for(let j=0;j<=i;j++)acc.sumXX[i][j]+=x[i]*x[j];for(let c=0;c<acc.leakageDim;c++)acc.sumXY[i][c]+=x[i]*y[c];}
  for(let c=0;c<acc.leakageDim;c++){acc.sumY[c]+=y[c];acc.sumY2+=y[c]*y[c];}
}

function finalizeAccumulator(acc,options={}){
  const n=acc.rows,h=acc.hiddenDim,l=acc.leakageDim;if(!n)return {status:'empty'};
  const lambda=Math.max(1e-12,Number(options.lambda??1e-6));if(!Number.isFinite(lambda))throw new Error('grouped profile lambda 非法');
  const meanX=acc.sumX.map((v)=>v/n),meanY=acc.sumY.map((v)=>v/n);
  const centeredGram=Array.from({length:h},()=>Array(h).fill(0));const centeredCross=Array.from({length:h},()=>Array(l).fill(0));
  for(let i=0;i<h;i++){
    for(let j=0;j<=i;j++){const raw=acc.sumXX[i][j]-n*meanX[i]*meanX[j];centeredGram[i][j]=raw;centeredGram[j][i]=raw;}
    for(let c=0;c<l;c++)centeredCross[i][c]=acc.sumXY[i][c]-n*meanX[i]*meanY[c];
  }
  const regularized=centeredGram.map((row)=>row.slice());for(let i=0;i<h;i++)regularized[i][i]+=lambda;
  const L=cholesky(regularized,Number(options.tolerance)||1e-12);if(!L)return {status:'rank-deficient',rows:n,hiddenDim:h,leakageDim:l,lambda};
  const weights=solveCholeskyMany(L,centeredCross);const intercept=Array(l).fill(0);
  for(let c=0;c<l;c++){let v=meanY[c];for(let d=0;d<h;d++)v-=meanX[d]*weights[d][c];intercept[c]=v;}
  const sst=Math.max(0,acc.sumY2-n*meanY.reduce((s,v)=>s+v*v,0));let crossTerm=0,quad=0;
  for(let d=0;d<h;d++)for(let c=0;c<l;c++)crossTerm+=weights[d][c]*centeredCross[d][c];
  for(let i=0;i<h;i++)for(let j=0;j<h;j++){let dot=0;for(let c=0;c<l;c++)dot+=weights[i][c]*weights[j][c];quad+=centeredGram[i][j]*dot;}
  const sse=Math.max(0,sst-2*crossTerm+quad);const count=n*l;
  return {schema:'newcyber.sca-group-profile.v1',status:'ok',method:'streaming-ridge-grouped',rows:n,hiddenDim:h,leakageDim:l,lambda,intercept,weights,rmse:Math.sqrt(sse/Math.max(1,count)),r2:sst>0?1-sse/sst:null};
}

async function fitGroupedLeakageProfiles(hiddenStates,rowSource,layout,options={}){
  const tokens=hiddenStates.length;if(!tokens||tokens>MAX_PROFILE_TOKENS)return {status:'token-budget-gap',tokens,limit:MAX_PROFILE_TOKENS};
  if(rowSource.rows!==tokens*layout.groupsPerToken)return {status:'row-mismatch',detail:`trace rows=${rowSource.rows} expected=${tokens*layout.groupsPerToken}`};
  if(rowSource.cols!==layout.rowFeatureDim)return {status:'feature-mismatch'};
  for(let i=0;i<tokens;i++)finiteMatrixRow(hiddenStates[i],layout.hiddenDim,`hiddenStates[${i}]`);
  const accs=Array.from({length:layout.groupsPerToken},()=>accumulator(layout.hiddenPerGroup,rowSource.cols));
  const rowsPerBatch=Math.max(layout.groupsPerToken,Math.floor(MAX_BATCH_VALUES/rowSource.cols/layout.groupsPerToken)*layout.groupsPerToken);
  for(let start=0;start<rowSource.rows;start+=rowsPerBatch){const count=Math.min(rowsPerBatch,rowSource.rows-start);const rows=await rowSource.readRows(start,count);for(let i=0;i<rows.length;i++){const global=start+i,token=Math.floor(global/layout.groupsPerToken),group=global%layout.groupsPerToken;const hs=hiddenStates[token].slice(group*layout.hiddenPerGroup,(group+1)*layout.hiddenPerGroup);updateAccumulator(accs[group],hs,rows[i]);}}
  const profiles=accs.map((acc,index)=>({...finalizeAccumulator(acc,options),group:index,hiddenStart:index*layout.hiddenPerGroup,hiddenEnd:(index+1)*layout.hiddenPerGroup}));
  const bad=profiles.find((p)=>p.status!=='ok');if(bad)return {status:'profile-gap',group:bad.group,profile:bad};
  const r2=profiles.map((p)=>p.r2).filter((v)=>v!=null);const rmse=profiles.map((p)=>p.rmse).filter(Number.isFinite);
  return {schema:'newcyber.sca-grouped-profile.v1',status:'ok',method:'streaming-ridge-token-groups',rows:tokens,rawRows:rowSource.rows,hiddenDim:layout.hiddenDim,leakageDim:layout.groupsPerToken*layout.rowFeatureDim,groupLeakageDim:layout.rowFeatureDim,groupsPerToken:layout.groupsPerToken,hiddenPerGroup:layout.hiddenPerGroup,solveDim:layout.hiddenPerGroup,r2:r2.length?r2.reduce((a,b)=>a+b,0)/r2.length:null,rmse:rmse.length?rmse.reduce((a,b)=>a+b,0)/rmse.length:null,profiles};
}

function recoverGroupHidden(profile,leakageRow,options={}){
  if(profile?.status!=='ok')return {status:'profile-gap'};const y=finiteMatrixRow(leakageRow,profile.leakageDim,'target grouped leakage');
  const A=Array.from({length:profile.leakageDim},(_,c)=>Array.from({length:profile.hiddenDim},(_,d)=>Number(profile.weights[d][c])));const b=y.map((v,c)=>v-Number(profile.intercept[c]||0));
  const solved=pseudoinverseSolve(A,b,{lambda:Math.max(0,Number(options.lambda??1e-10))});return {status:solved.status,hidden:solved.solution||null,method:solved.method||null};
}

async function recoverGroupedTargets(profile,rowSource,probeMatrix,probeOptions={}){
  if(profile?.status!=='ok')return {status:'profile-gap'};const groups=profile.groupsPerToken;if(rowSource.rows%groups!==0)return {status:'target-row-mismatch',detail:`target rows=${rowSource.rows} 不能整除 groups=${groups}`};
  const tokens=rowSource.rows/groups;if(tokens<=0||tokens>MAX_TARGET_TOKENS)return {status:'target-token-budget-gap',tokens,limit:MAX_TARGET_TOKENS};
  const hiddenStates=[];const candidates=[];
  for(let token=0;token<tokens;token++){
    const rows=await rowSource.readRows(token*groups,groups);const hidden=[];
    for(let g=0;g<groups;g++){const recovered=recoverGroupHidden(profile.profiles[g],rows[g],probeOptions.recovery||{});if(recovered.status!=='ok')return {status:'group-recovery-gap',token,group:g,detail:recovered.status};hidden.push(...recovered.hidden);}
    const ranking=rankProbeCandidates(hidden,probeMatrix,probeOptions.probe||{});if(ranking.status!=='ok')return {status:ranking.status,token,ranking};hiddenStates.push(hidden);candidates.push(ranking.top);
  }
  return {schema:'newcyber.sca-grouped-target.v1',status:'ok',tokens,hiddenStates,candidates};
}

module.exports={MAX_GROUPS,MAX_PROFILE_TOKENS,MAX_TARGET_TOKENS,sourceGroupingEvidence,resolveGroupedLayout,fitGroupedLeakageProfiles,recoverGroupedTargets};
