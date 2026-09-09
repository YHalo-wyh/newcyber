'use strict';

const v2 = require('./secret_flag_recovery_v2');

function recoverFlagFromSecret(secretSigned, options = {}) {
  const files = Array.isArray(options.files) ? options.files : [];
  const sourceText = options.sourceText || files
    .filter((file) => /\.(?:py|pyw|js|ts|go|rs|java|c|cc|cpp|h|hpp)$/i.test(file.name || '') && Buffer.isBuffer(file.buffer) && file.buffer.length <= 1024 * 1024)
    .slice(0, 12)
    .map((file) => `# FILE: ${file.name}\n${file.buffer.toString('utf8')}`)
    .join('\n\n');
  return v2.recoverFlagFromSecret(secretSigned, { ...options, sourceText });
}

module.exports = { ...v2, recoverFlagFromSecret };
