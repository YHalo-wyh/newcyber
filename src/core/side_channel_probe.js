'use strict';

const { pseudoinverseSolve } = require('./power_side_channel');

const MAX_ROWS = 50000;
const MAX_HIDDEN_DIM = 4096;
const MAX_SOLVE_DIM = 1024;
const MAX_LEAKAGE_DIM = 1024;
const MAX_PROBE_CANDIDATES = 200000;

function matrixShape(matrix,label='matrix') {
  if (!Array.isArray(matrix) || !matrix.length || !Array.isArray(matrix[0]) || !matrix[0].length) throw new Error(`${label} 为空`);
  const cols=matrix[0].length;
  if (matrix.length>MAX_ROWS) throw new Error(`${label} rows 超过 ${MAX_ROWS}`);
  for(const row of matrix){
    if(!Array.isArray(row)||row.length!==cols||row.some((v)=>!Number.isFinite(Number(v)))) throw new Error(`${label} 必须是规则有限数值矩阵`);
  }
  return [matrix.length,cols];
}

function cholesky(matrix,tolerance=1e-12){
  const n=matrix.length;
  const L=Array.from({length:n},()=>Array(n).fill(0));
  for(let i=0;i<n;i+=1){
    for(let j=0;j<=i;j+=1){
      let sum=matrix[i][j];
      for(let k=0;k<j;k+=1) sum-=L[i][k]*L[j][k];
      if(i===j){
        if(!Number.isFinite(sum)||sum<=tolerance) return null;
        L[i][j]=Math.sqrt(sum);
      } else L[i][j]=sum/L[j][j];
    }
  }
  return L;
}

function solveCholeskyMany(L,rhs){
  const n=L.length;
  const cols=rhs[0].length;
  const y=Array.from({length:n},()=>Array(cols).fill(0));
  for(let i=0;i<n;i+=1){
    for(let c=0;c<cols;c+=1){
      let value=rhs[i][c];
      for(let k=0;k<i;k+=1)value-=L[i][k]*y[k][c];
      y[i][c]=value/L[i][i];
    }
  }
  const x=Array.from({length:n},()=>Array(cols).fill(0));
  for(let i=n-1;i>=0;i-=1){
    for(let c=0;c<cols;c+=1){
      let value=y[i][c];
      for(let k=i+1;k<n;k+=1)value-=L[k][i]*x[k][c];
      x[i][c]=value/L[i][i];
    }
  }
  return x;
}

function columnMeans(matrix){
  const [rows,cols]=matrixShape(matrix);
  const means=Array(cols).fill(0);
  for(const row of matrix)for(let c=0;c<cols;c+=1)means[c]+=Number(row[c]);
  for(let c=0;c<cols;c+=1)means[c]/=rows;
  return means;
}

function centerMatrix(matrix,means){
  return matrix.map((row)=>row.map((value,index)=>Number(value)-Number(means[index]||0)));
}

function fitLeakageProfile(hiddenStates,leakageFeatures,options={}){
  const [rows,hiddenDim]=matrixShape(hiddenStates,'hiddenStates');
  const [leakRows,leakDim]=matrixShape(leakageFeatures,'leakageFeatures');
  if(rows!==leakRows) throw new Error('hiddenStates 与 leakageFeatures 行数不一致');
  if(hiddenDim>MAX_HIDDEN_DIM) return {schema:'newcyber.sca-leakage-profile.v1',status:'hidden-budget-gap',rows,hiddenDim,leakageDim:leakDim,limit:MAX_HIDDEN_DIM};
  if(leakDim>MAX_LEAKAGE_DIM) return {schema:'newcyber.sca-leakage-profile.v1',status:'leakage-budget-gap',rows,hiddenDim,leakageDim:leakDim,limit:MAX_LEAKAGE_DIM};
  const solveDim=Math.min(rows,hiddenDim);
  if(solveDim>MAX_SOLVE_DIM) return {schema:'newcyber.sca-leakage-profile.v1',status:'dimension-budget-gap',rows,hiddenDim,leakageDim:leakDim,solveDim,limit:MAX_SOLVE_DIM};
  const intercept=options.intercept!==false;
  const lambda=Math.max(0,Number(options.lambda??1e-8));
  if(!Number.isFinite(lambda)) throw new Error('lambda 非法');
  if(lambda===0&&rows<hiddenDim) return {schema:'newcyber.sca-leakage-profile.v1',status:'underdetermined',rows,hiddenDim,leakageDim:leakDim,parameters:hiddenDim};

  const hiddenMean=intercept?columnMeans(hiddenStates):Array(hiddenDim).fill(0);
  const leakageMean=intercept?columnMeans(leakageFeatures):Array(leakDim).fill(0);
  const X=intercept?centerMatrix(hiddenStates,hiddenMean):hiddenStates.map((row)=>row.map(Number));
  const Y=intercept?centerMatrix(leakageFeatures,leakageMean):leakageFeatures.map((row)=>row.map(Number));
  let weights;
  let method;

  if(hiddenDim<=rows){
    method='ridge-primal-cholesky';
    const gram=Array.from({length:hiddenDim},()=>Array(hiddenDim).fill(0));
    const cross=Array.from({length:hiddenDim},()=>Array(leakDim).fill(0));
    for(let r=0;r<rows;r+=1){
      for(let i=0;i<hiddenDim;i+=1){
        const xi=X[r][i];
        for(let j=0;j<=i;j+=1)gram[i][j]+=xi*X[r][j];
        for(let c=0;c<leakDim;c+=1)cross[i][c]+=xi*Y[r][c];
      }
    }
    for(let i=0;i<hiddenDim;i+=1){
      for(let j=0;j<i;j+=1)gram[j][i]=gram[i][j];
      gram[i][i]+=lambda;
    }
    const L=cholesky(gram,Number(options.tolerance)||1e-12);
    if(!L)return {schema:'newcyber.sca-leakage-profile.v1',status:'rank-deficient',method,rows,hiddenDim,leakageDim:leakDim,lambda,solveDim:hiddenDim};
    weights=solveCholeskyMany(L,cross);
  } else {
    method='ridge-dual-cholesky';
    const gram=Array.from({length:rows},()=>Array(rows).fill(0));
    for(let i=0;i<rows;i+=1){
      for(let j=0;j<=i;j+=1){
        let value=0;
        for(let d=0;d<hiddenDim;d+=1)value+=X[i][d]*X[j][d];
        gram[i][j]=value;
      }
    }
    for(let i=0;i<rows;i+=1){
      for(let j=0;j<i;j+=1)gram[j][i]=gram[i][j];
      gram[i][i]+=lambda;
    }
    const L=cholesky(gram,Number(options.tolerance)||1e-12);
    if(!L)return {schema:'newcyber.sca-leakage-profile.v1',status:'rank-deficient',method,rows,hiddenDim,leakageDim:leakDim,lambda,solveDim:rows};
    const alpha=solveCholeskyMany(L,Y);
    weights=Array.from({length:hiddenDim},()=>Array(leakDim).fill(0));
    for(let d=0;d<hiddenDim;d+=1){
      for(let r=0;r<rows;r+=1){
        const x=X[r][d];
        for(let c=0;c<leakDim;c+=1)weights[d][c]+=x*alpha[r][c];
      }
    }
  }

  const interceptVector=Array(leakDim).fill(0);
  if(intercept){
    for(let c=0;c<leakDim;c+=1){
      let value=leakageMean[c];
      for(let d=0;d<hiddenDim;d+=1)value-=hiddenMean[d]*weights[d][c];
      interceptVector[c]=value;
    }
  }
  let sse=0;let sst=0;let count=0;
  for(let r=0;r<rows;r+=1){
    for(let c=0;c<leakDim;c+=1){
      let pred=interceptVector[c];
      for(let d=0;d<hiddenDim;d+=1)pred+=Number(hiddenStates[r][d])*weights[d][c];
      const actual=Number(leakageFeatures[r][c]);
      const err=actual-pred;sse+=err*err;
      const centered=actual-leakageMean[c];sst+=centered*centered;count+=1;
    }
  }
  return {
    schema:'newcyber.sca-leakage-profile.v1',status:'ok',method,rows,hiddenDim,leakageDim:leakDim,solveDim,lambda,
    intercept:interceptVector,weights,rmse:Math.sqrt(sse/Math.max(1,count)),r2:sst>0?1-sse/sst:null
  };
}

function recoverHiddenState(profile,leakageVector,options={}){
  if(profile?.status!=='ok') return {schema:'newcyber.sca-hidden-recovery.v1',status:'profile-gap'};
  const leakage=Array.from(leakageVector||[],Number);
  if(leakage.length!==profile.leakageDim||leakage.some((v)=>!Number.isFinite(v))) throw new Error('target leakage 维数与 profile 不一致');
  const A=Array.from({length:profile.leakageDim},(_,c)=>Array.from({length:profile.hiddenDim},(_,d)=>Number(profile.weights[d][c])));
  const b=leakage.map((value,c)=>value-Number(profile.intercept[c]||0));
  const solved=pseudoinverseSolve(A,b,{lambda:Math.max(0,Number(options.lambda??1e-10))});
  return {
    schema:'newcyber.sca-hidden-recovery.v1',status:solved.status==='ok'?'ok':solved.status,method:solved.method||null,
    hidden:solved.solution||null,residual:solved.residual||null,source:{hiddenDim:profile.hiddenDim,leakageDim:profile.leakageDim}
  };
}

function dot(a,b){let sum=0;for(let i=0;i<a.length;i+=1)sum+=Number(a[i])*Number(b[i]);return sum;}
function norm(a){return Math.sqrt(dot(a,a));}

function rankProbeCandidates(hiddenVector,probeMatrix,options={}){
  const hidden=Array.from(hiddenVector||[],Number);
  if(!hidden.length||hidden.some((v)=>!Number.isFinite(v))) throw new Error('hidden vector 非法');
  const [rows,cols]=matrixShape(probeMatrix,'probeMatrix');
  let orientation=options.orientation||null;
  if(!orientation){
    const rowMatch=cols===hidden.length;
    const colMatch=rows===hidden.length;
    if(rowMatch===colMatch) return {schema:'newcyber.sca-probe-ranking.v1',status:'orientation-gap',shape:[rows,cols],hiddenDim:hidden.length};
    orientation=rowMatch?'candidate-rows':'candidate-cols';
  }
  if(!['candidate-rows','candidate-cols'].includes(orientation)) throw new Error('probe orientation 必须是 candidate-rows 或 candidate-cols');
  const candidateCount=orientation==='candidate-rows'?rows:cols;
  if(candidateCount>MAX_PROBE_CANDIDATES) return {schema:'newcyber.sca-probe-ranking.v1',status:'candidate-budget-gap',candidates:candidateCount,limit:MAX_PROBE_CANDIDATES};
  if((orientation==='candidate-rows'?cols:rows)!==hidden.length) throw new Error('probe hidden 维与 recovered hidden 不一致');
  const ids=Array.isArray(options.candidateIds)?options.candidateIds.map(Number):null;
  if(ids&&ids.length!==candidateCount) throw new Error('candidateIds 数量与 probe candidates 不一致');
  const metric=String(options.metric||'dot').toLowerCase();
  if(!['dot','cosine','negative-l2'].includes(metric)) throw new Error(`不支持 probe metric ${metric}`);
  const hnorm=norm(hidden)||1;
  const ranked=[];
  for(let i=0;i<candidateCount;i+=1){
    const vector=orientation==='candidate-rows'?probeMatrix[i].map(Number):Array.from({length:rows},(_,r)=>Number(probeMatrix[r][i]));
    let score;
    if(metric==='cosine') score=dot(hidden,vector)/(hnorm*(norm(vector)||1));
    else if(metric==='negative-l2'){let s=0;for(let d=0;d<hidden.length;d+=1){const e=hidden[d]-vector[d];s+=e*e;}score=-s;}
    else score=dot(hidden,vector);
    ranked.push({index:i,tokenId:ids?ids[i]:i,score});
  }
  ranked.sort((a,b)=>b.score-a.score||a.index-b.index);
  const topK=Math.max(1,Math.min(256,Number(options.topK)||32));
  return {schema:'newcyber.sca-probe-ranking.v1',status:'ok',orientation,metric,hiddenDim:hidden.length,candidates:candidateCount,top:ranked.slice(0,topK)};
}

function recoverProbeCandidates(profile,targetLeakage,probeMatrix,options={}){
  const hidden=recoverHiddenState(profile,targetLeakage,options.recovery||{});
  if(hidden.status!=='ok') return {schema:'newcyber.sca-probe-chain.v1',status:hidden.status,hidden,ranking:null};
  const ranking=rankProbeCandidates(hidden.hidden,probeMatrix,options.probe||{});
  return {schema:'newcyber.sca-probe-chain.v1',status:ranking.status==='ok'?'ok':ranking.status,hidden,ranking};
}

module.exports={
  MAX_HIDDEN_DIM,MAX_SOLVE_DIM,MAX_LEAKAGE_DIM,
  fitLeakageProfile,recoverHiddenState,rankProbeCandidates,recoverProbeCandidates
};
