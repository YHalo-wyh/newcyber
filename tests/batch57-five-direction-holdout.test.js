'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {
  DIRECTIONS,CASES_PER_DIRECTION,TOTAL_CASES,runBatch57FiveDirectionHoldout
}=require('../src/core/ai_batch57_five_direction_holdout');

test('Batch57 five-direction 120-case holdout gate passes across representation changes',()=>{
  const report=runBatch57FiveDirectionHoldout();
  assert.equal(TOTAL_CASES,120);
  assert.equal(report.summary.total,120);
  assert.equal(report.summary.failed,0,report.results.filter((x)=>!x.pass).map((x)=>`${x.id}: expected=${x.expected} actual=${x.actual}${x.error?` error=${x.error}`:''}`).join('\n'));
  assert.equal(report.summary.passed,120);
  assert.equal(report.summary.passRate,1);
  for(const direction of DIRECTIONS){
    const summary=report.summary.directions[direction];
    assert.equal(summary.total,CASES_PER_DIRECTION,direction);
    assert.equal(summary.passed,CASES_PER_DIRECTION,direction);
    assert.ok(summary.holdoutTotal>=12,direction);
    assert.equal(summary.holdoutPassed,summary.holdoutTotal,direction);
  }
  assert.equal(report.policy.realCtfCountExcluded,true);
  assert.equal(report.policy.noAnswerMemorization,true);
});

test('Batch57 holdout result surface contains no raw prompt/secret/model payloads',()=>{
  const report=runBatch57FiveDirectionHoldout();
  const serialized=JSON.stringify(report);
  assert.doesNotMatch(serialized,/holdout_\d+\}|pip['"]\s*,\s*['"]install|trust_remote_code=True/);
  assert.ok(report.results.every((row)=>!Object.hasOwn(row,'input')));
});
