const base = require('./evm_runtime');
const { analyzeEvmProxy } = require('./evm_proxy');

function analyzeEvmRuntime(input) {
  const result = base.analyzeEvmRuntime(input);
  const proxy = analyzeEvmProxy(input, result);
  return {
    ...result,
    proxy,
    notes: [
      ...(result.notes || []),
      'proxy 层额外识别 EIP-1167 canonical runtime 与 EIP-1967 implementation/admin/beacon slot，并要求 storage→DELEGATECALL 的真实局部数据流证据后才给高置信。'
    ]
  };
}

module.exports = {
  ...base,
  analyzeEvmRuntime
};
