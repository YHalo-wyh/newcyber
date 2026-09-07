const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeTabularDataset } = require('../src/core/ai_tabular');

test('长城杯 The Silent Heist 类数据：输出多维统计画像与相关性', () => {
  const csv = `amount,f1,f2,f3,f4
1000,1,10,100,5
1100,2,20,102,6
1200,3,30,104,7
1300,4,40,106,8
1400,5,50,108,9
1500,6,60,110,10`;
  const result = analyzeTabularDataset(csv);
  assert.equal(result.rows, 6);
  assert.equal(result.numericColumns, 5);
  assert.equal(result.centerProfile.f1, 3.5);
  assert.ok(result.strongestCorrelations.some((item) => item.left === 'f1' && item.right === 'f2' && Math.abs(item.correlation) === 1));
  assert.ok(result.findings.some((item) => item.id === 'multivariate-profile'));
  assert.ok(result.centerRows.length > 0);
});

test('欺诈模型 API 类输入：显式暴露 NaN/Inf 边界', () => {
  const csv = `trans_amount_usd,addr_deviation_score,risk
NaN,0.95,0.99
Infinity,0.91,0.98
1000,0.20,0.10`;
  const result = analyzeTabularDataset(csv);
  assert.equal(result.nonFiniteCells.length, 2);
  assert.ok(result.findings.some((item) => item.id === 'non-finite-input'));
  assert.deepEqual(result.nonFiniteCells.map((item) => item.value), ['NaN', 'Infinity']);
});

test('CSV quoted fields remain aligned', () => {
  const result = analyzeTabularDataset('name,f1,f2\n"alpha,beta",1,2\ngamma,3,4');
  assert.equal(result.rows, 2);
  assert.equal(result.columnStats.find((item) => item.name === 'f1').mean, 2);
});
