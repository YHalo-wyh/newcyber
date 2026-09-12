'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { extractFields } = require('../src/core/ai_leakage');

test('leakage field extractor keeps the recovered ID and phone explicit', () => {
  assert.deepEqual(extractFields('Target Profile:\nID: 11010119880912564X\nSignal: 13855225864'), {
    id: '11010119880912564X', phone: '13855225864'
  });
});
