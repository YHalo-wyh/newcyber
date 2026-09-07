const base = require('./formats');
const { parsePcapng } = require('./pcapng');

function analyzeKnownFormat(buffer, type, extension) {
  if (type === 'PCAPNG 流量' || extension === '.pcapng') return parsePcapng(buffer);
  return base.analyzeKnownFormat(buffer, type, extension);
}

module.exports = { ...base, analyzeKnownFormat, parsePcapng };
