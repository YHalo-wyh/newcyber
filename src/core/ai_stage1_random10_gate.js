'use strict';

const {runStage1WorldwideHoldoutBatch82}=require('./ai_stage1_worldwide_holdout_batch82');

function choose(n,k){
  n=Math.trunc(n);k=Math.trunc(k);if(k<0||n<0||k>n)return 0;k=Math.min(k,n-k);let out=1;
  for(let i=1;i<=k;i++)out=out*(n-k+i)/i;
  return out;
}
function hypergeometricPmf(population,successes,draws,hits){
  if([population,successes,draws,hits].some((x)=>!Number.isInteger(x)))return 0;
  if(population<0||successes<0||successes>population||draws<0||draws>population)return 0;
  if(hits<0||hits>successes||draws-hits>population-successes)return 0;
  const denom=choose(population,draws);return denom?choose(successes,hits)*choose(population-successes,draws-hits)/denom:0;
}
function probabilityAtLeast(population,successes,draws,threshold){
  let p=0;for(let k=Math.max(0,threshold);k<=draws;k++)p+=hypergeometricPmf(population,successes,draws,k);return Math.min(1,Math.max(0,p));
}
function distribution(population,successes,draws){
  const out=[];for(let k=0;k<=draws;k++){const p=hypergeometricPmf(population,successes,draws,k);if(p>0)out.push({solved:k,probability:p});}return out;
}
function quantile(rows,q){
  let cumulative=0;for(const row of rows){cumulative+=row.probability;if(cumulative+1e-15>=q)return row.solved;}return rows.at(-1)?.solved??null;
}
function runRandom10Gate(options={}){
  const benchmark=options.benchmark||runStage1WorldwideHoldoutBatch82();
  const population=benchmark.summary.cases;const successes=benchmark.summary.closed;const draws=Math.min(10,population);const target=Math.min(7,draws);
  const dist=distribution(population,successes,draws);
  const atLeast7=probabilityAtLeast(population,successes,draws,target);
  const expected=population?draws*successes/population:0;
  const byDirection=Object.fromEntries(Object.entries(benchmark.byDirection||{}).map(([direction,row])=>[direction,{cases:row.cases,closed:row.closed,rate:row.solveProxyRate}]));
  const weakest=Object.entries(byDirection).sort((a,b)=>a[1].rate-b[1].rate||a[0].localeCompare(b[0])).map(([direction,row])=>({direction,...row}));
  return{
    schema:'newcyber.ai-stage1-random10-gate.v1',
    population,successes,draws,target,
    solveProxyRate:benchmark.summary.solveProxyRate,
    probabilityAtLeast7:atLeast7,
    expectedSolved:expected,
    p10:quantile(dist,0.10),median:quantile(dist,0.50),p90:quantile(dist,0.90),
    distribution:dist,byDirection,weakestDirections:weakest.slice(0,3),
    pass:benchmark.summary.solveProxyRate>=0.70&&atLeast7>=0.70,
    notes:[
      '这是从当前公开 source-derived holdout 中“不放回随机抽 10 题”的精确超几何代理，不是未来比赛真实成功率预测。',
      '只把 status=closed 计为“出题”；partial 一律按未出题处理，因此不会靠半成品抬高 7/10 指标。',
      '真正提高比赛胜率应优先补 weakestDirections 与 holdout 中仍为 partial/gap 的生成型 executor，而不是只往测试集加入已会的同类题。'
    ]
  };
}

module.exports={choose,hypergeometricPmf,probabilityAtLeast,distribution,runRandom10Gate};
