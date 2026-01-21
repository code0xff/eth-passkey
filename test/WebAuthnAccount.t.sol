// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import 'forge-std/Test.sol';
import 'forge-std/console.sol';
import '../contracts/WebAuthnP256.sol';
import '../contracts/WebAuthnAccount.sol';
import '../node_modules/@openzeppelin/contracts/utils/Base64.sol';

contract WebAuthnAccountTest is Test {
	WebAuthnAccount wallet;
	address owner;
	address relayer;

	function setUp() public {
		owner = 0x19F9Bfb3DA082A36DAb282deD1F71e8492991378;
		relayer = 0xC1497d7EC8C5ade926958E2D38BB7b9Df78832b3;

		// vm.prank(owner);
		// verifier = new WebAuthnP256();
		// console.log('Contract Address:', address(verifier));
	}

	function test_WebAuthnAccount_verify() public {
		bytes32 challenge = 0x1821586f068bf0b53f5e19c89bb55e035a4c34319c94e4089a35b2a15fc5b0be;
		string memory challengeBase64Url = Base64.encodeURL(abi.encodePacked(challenge));

		console.log('challengeBase64Url', challengeBase64Url);

		WebAuthnP256.Metadata memory metadata = WebAuthnP256.Metadata({
			authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
			clientDataJSON: '{"type":"webauthn.get","challenge":"GCFYbwaL8LU_XhnIm7VeA1pMNDGclOQImjWyoV_FsL4","origin":"http://localhost:5173","crossOrigin":false}',
			challengeIndex: 23,
			typeIndex: 1,
			userVerificationRequired: true
		});

		ECDSA.Signature memory signature = ECDSA.Signature({
			r: 0x3fa870f1586f3450c083a020e9bc0b73507d55835588428c7295a22c9962e834,
			s: 0x29765fa484b426a85c9f5081ba76b01f0cbfe54c1ef6817fa45e504f276f619a
		});

		ECDSA.PublicKey memory publicKey = ECDSA.PublicKey({
			x: 0xf305e748e6b6d47549b2a2daab2edc25ef6b441438ab0208b41e726cd19b9c87,
			y: 0xfb4b4ca5f4daa703ac3862fc5db62da2c1953c044755b938f983e6c8a7a47f0e
		});

		bool ok = WebAuthnP256.verify(challenge, metadata, signature, publicKey);
		console.log("verify result", ok);
	}
}
