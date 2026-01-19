// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import './ECDSA.sol';
import './WebAuthnP256.sol';

contract WebAuthn7702 {
	struct WebAuthnKey {
		uint256 x;
		uint256 y;
		bool enabled;
	}

	mapping(bytes32 => WebAuthnKey) public keys;
	mapping(bytes32 => uint256) public nonces;

	event Executed(
		bytes32 indexed credentialId,
		address indexed to,
		uint256 value,
		bytes data,
		bytes result
	);
	event KeyUpdated(bytes32 indexed credentialId, uint256 x, uint256 y, bool enabled);

	error CallFailed();
	error DeadlineExpired();
	error InvalidKey();
	error Unauthorized();
	error WebAuthnVerifyFailed();

	modifier onlySelf() {
		if (msg.sender != address(this)) revert Unauthorized();
		_;
	}

	bytes32 constant EXECUTE_DOMAIN = keccak256('WEBAUTHN_7702_EXECUTE');

	function setKey(
		bytes32 credentialIdHash,
		uint256 x,
		uint256 y,
		bool enabled
	) external onlySelf {
		keys[credentialIdHash] = WebAuthnKey(x, y, enabled);
		emit KeyUpdated(credentialIdHash, x, y, enabled);
	}

	function challengeExecute(
		bytes32 credentialIdHash,
		address to,
		uint256 value,
		uint256 nonce,
		bytes calldata data,
		uint256 deadline
	) public view returns (bytes32) {
		return
			keccak256(
				abi.encode(
					EXECUTE_DOMAIN,
					block.chainid,
					address(this),
					credentialIdHash,
					to,
					value,
					keccak256(data),
					nonce,
					deadline
				)
			);
	}

	function _checkDeadline(uint256 deadline) internal view virtual {
		if (deadline != 0 && block.timestamp > deadline) revert DeadlineExpired();
	}

	function execute(
		bytes32 credentialIdHash,
		address to,
		uint256 value,
		bytes calldata data,
		uint256 deadline,
		WebAuthnP256.Metadata calldata metadata,
		ECDSA.Signature calldata signature
	) external payable returns (bytes memory) {
		WebAuthnKey memory key = keys[credentialIdHash];
		if (!key.enabled || key.x == 0) revert InvalidKey();

		_checkDeadline(deadline);

		ECDSA.PublicKey memory publicKey = ECDSA.PublicKey({x: key.x, y: key.y});
		uint256 nonce = nonces[credentialIdHash];

		bytes32 challenge = challengeExecute(credentialIdHash, to, value, nonce, data, deadline);
		bool ok = WebAuthnP256.verify(challenge, metadata, signature, publicKey);
		if (!ok) revert WebAuthnVerifyFailed();

		nonces[credentialIdHash]++;

		(bool success, bytes memory result) = to.call{value: value}(data);
		if (!success) revert CallFailed();

		emit Executed(credentialIdHash, to, value, data, result);

		return result;
	}

	receive() external payable {}
}
