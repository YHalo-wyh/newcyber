const base = require('./low_altitude');
const { reconstructMavFtpFiles } = require('./mavlink_ftp_reassembly');

function analyzeMavlinkAdvanced(input) {
  const result = base.analyzeMavlinkAdvanced(input);
  const ftpReassembly = reconstructMavFtpFiles(result.ftpEvents || []);
  return {
    ...result,
    ftpReassembly,
    securitySummary: {
      ...(result.securitySummary || {}),
      ftpCompleteFiles: ftpReassembly.completeFiles,
      ftpExportableFiles: ftpReassembly.exportableFiles
    }
  };
}

module.exports = { ...base, analyzeMavlinkAdvanced, reconstructMavFtpFiles };
