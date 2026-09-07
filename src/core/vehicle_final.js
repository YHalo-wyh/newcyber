const vehicle = require('./vehicle');
const { reconstructUdsProgramming } = require('./uds_programming');

function analyzeCanAdvanced(text) {
  const result = vehicle.analyzeCanAdvanced(text);
  return {
    ...result,
    udsProgramming: reconstructUdsProgramming(result.isoTpSessions || []),
    hints: [
      ...(result.hints || []),
      '检测到 0x34/0x36/0x37 刷写链时，udsProgramming 会重组 TransferData 数据并给出 firmware SHA-256；出现 block gap 时不要把候选当完整固件。'
    ]
  };
}

module.exports = {
  ...vehicle,
  analyzeCanAdvanced
};
