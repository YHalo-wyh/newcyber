const test = require('node:test');
const assert = require('node:assert/strict');
const { auditSolidity } = require('../src/core/web3');

const SUCTF_MAGICBOX = `
pragma solidity 0.8.28;
contract MagicBox {
    struct Signature { uint8 v; bytes32 r; bytes32 s; }
    address magician;
    bytes32 alreadyUsedSignatureHash;

    function getMessageHash(address _magician) public view returns (bytes32) {
        return keccak256(abi.encodePacked("I want to open the magic box", _magician, address(this), block.chainid));
    }

    function _getSignerAndSignatureHash(Signature memory _signature) internal view returns (address, bytes32) {
        address signer = ecrecover(getMessageHash(msg.sender), _signature.v, _signature.r, _signature.s);
        bytes32 signatureHash = keccak256(abi.encodePacked(_signature.v, _signature.r, _signature.s));
        return (signer, signatureHash);
    }

    function openBox(Signature memory signature) external {
        (address signer, bytes32 signatureHash) = _getSignerAndSignatureHash(signature);
        require(signer == msg.sender, "Invalid signature");
        require(signatureHash != alreadyUsedSignatureHash, "Signature already used");
    }
}
`;

test('SUCTF 2025 Onchain Magician: raw signature hash replay guard 命中 ECDSA 延展性', () => {
  const result = auditSolidity(SUCTF_MAGICBOX);
  const finding = result.findings.find((item) => item.id === 'ecdsa-signature-hash-replay');
  assert.ok(finding);
  assert.equal(finding.severity, 'high');
  assert.match(finding.message, /low-s|规范化|重放/);
});

test('ECDSA replay guard: 显式 low-s canonicalization 不报签名延展性', () => {
  const source = `
    pragma solidity ^0.8.20;
    contract SafeRecover {
      bytes32 usedSignatureHash;
      function verify(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "high-s");
        address signer = ecrecover(digest, v, r, s);
        bytes32 signatureHash = keccak256(abi.encodePacked(v, r, s));
        require(signatureHash != usedSignatureHash, "used");
        usedSignatureHash = signatureHash;
        require(signer != address(0));
      }
    }
  `;
  const result = auditSolidity(source);
  assert.equal(result.findings.some((item) => item.id === 'ecdsa-signature-hash-replay'), false);
});
