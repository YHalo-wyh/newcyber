const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function read(name) {
  return fs.readFileSync(path.join(__dirname, '..', 'renderer', name), 'utf8');
}

test('batch-two renderer extensions stay compilable', () => {
  for (const name of ['mavlink_ftp_tools.js', 'ai_tabular_tools.js', 'uds_programming_tools.js']) {
    assert.doesNotThrow(() => new vm.Script(read(name), { filename: `renderer/${name}` }));
  }
});

test('toolbox loads batch-two extensions after finals base in dependency order', () => {
  const html = read('toolbox.html');
  const finals = html.indexOf('finals_tools.js');
  const mavlink = html.indexOf('mavlink_ftp_tools.js');
  const evm = html.indexOf('evm_runtime_tools.js');
  const tabular = html.indexOf('ai_tabular_tools.js');
  const uds = html.indexOf('uds_programming_tools.js');
  assert.ok(finals >= 0);
  assert.ok(mavlink > finals);
  assert.ok(evm > mavlink);
  assert.ok(tabular > evm);
  assert.ok(uds > tabular);
});
