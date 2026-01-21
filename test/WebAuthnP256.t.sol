// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import 'forge-std/Test.sol';
import 'forge-std/console.sol';
import '../contracts/WebAuthnP256.sol';
import '../node_modules/@openzeppelin/contracts/utils/Base64.sol';

contract WebAuthnP256Test is Test {
	function test_WebAuthnP256_verify() public view {
		bytes32 challenge = 0x179d55048fafcdaeb73bf815c88c073edf29a53be106d639ba136fdf99528fe6;
		string memory challengeBase64Url = Base64.encodeURL(abi.encodePacked(challenge));

		console.log('challengeBase64Url', challengeBase64Url);

		WebAuthnP256.Metadata memory metadata = WebAuthnP256.Metadata({
			authenticatorData: hex'49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000',
			clientDataJSON: '{"type":"webauthn.get","challenge":"F51VBI-vza63O_gVyIwHPt8ppTvhBtY5uhNv35lSj-Y","origin":"http://localhost:5173","crossOrigin":false}',
			challengeIndex: 23,
			typeIndex: 1,
			userVerificationRequired: true
		});

		ECDSA.Signature memory signature = ECDSA.Signature({
			r: 0x88e37ddd801410c3fc6f0e7fde86b6c7154f9afad8a4cd1d3303092cfaf1622d,
			s: 0x184d6939fd72f8b273ea6323a441c7beffb7863b11321d550a0af4bfe779b219
		});

		ECDSA.PublicKey memory publicKey = ECDSA.PublicKey({
			x: 0x80b307c5a9a49714230d436a9b2dd09685d1ccb0b775bc7b03d6d691abf5184e,
			y: 0x2aed59f7ee14e98e9a5ac92c0960d22c940f2152120e5ef5d465ed77ed4ca6ba
		});

		bool ok = WebAuthnP256.verify(challenge, metadata, signature, publicKey);
		console.log('verify result', ok);
	}
}

// forge test --match-test test_WebAuthnP256_verify -vvvv
