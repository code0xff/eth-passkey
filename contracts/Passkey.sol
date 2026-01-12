// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PasskeyBound7702Account_WebAuthn
 * @notice EIP-7702 delegation logic authorized by WebAuthn Passkeys (secp256r1 / P-256).
 *
 * Threat model / design:
 * - We DO NOT parse clientDataJSON on-chain (too expensive / ambiguous).
 * - Instead, the client provides:
 *   - clientDataJSONHash = sha256(clientDataJSON)
 *   - challengeHashProvided (the challenge the user saw/confirmed in WebAuthn UI)
 * - On-chain we recompute expectedChallengeHash from (chainId, account, nonce, callsHash)
 *   and require equality. This binds the user's Passkey consent to the exact calls.
 * - We verify the WebAuthn signature over:
 *     signedBytesHash = sha256( authenticatorData || clientDataJSONHash )
 *   using the P-256 verify precompile at 0x100 (EIP-7951).
 */
contract PasskeyBound7702Account_WebAuthn {
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    struct Passkey {
        bytes32 qx;
        bytes32 qy;
        bool exists;
    }

    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(bytes32 => Passkey) public passkeys;
    uint256 public nonce;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event PasskeyAdded(bytes32 indexed keyId, bytes32 qx, bytes32 qy);
    event PasskeyRemoved(bytes32 indexed keyId);
    event Executed(
        bytes32 indexed keyId,
        uint256 indexed nonce,
        bytes32 expectedChallengeHash,
        bytes32 signedBytesHash,
        uint256 callsCount
    );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error OnlySelf();
    error PasskeyAlreadyExists(bytes32 keyId);
    error PasskeyNotFound(bytes32 keyId);
    error ChallengeMismatch(bytes32 expected, bytes32 provided);
    error InvalidPasskeySignature();
    error CallFailed(uint256 index, bytes reason);

    /*//////////////////////////////////////////////////////////////
                           CONSTANTS & PRECOMPILE
    //////////////////////////////////////////////////////////////*/

    // P-256 verify precompile per EIP-7951
    address internal constant P256VERIFY = address(0x0b);

    // Domain tag for challenge hashing (fixed, versioned)
    bytes32 internal constant CHALLENGE_DOMAIN =
        bytes32(sha256("PasskeyBound7702Account_WebAuthn:v1"));

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     * Admin functions restricted to "self".
     * In EIP-7702 flows, admin actions can be invoked by sending a tx to the EOA itself
     * (address(this)) while delegated to this code.
     */
    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelf();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                           PASSKEY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function addPasskey(
        bytes32 keyId,
        bytes32 qx,
        bytes32 qy
    ) external onlySelf {
        if (passkeys[keyId].exists) revert PasskeyAlreadyExists(keyId);
        passkeys[keyId] = Passkey({qx: qx, qy: qy, exists: true});
        emit PasskeyAdded(keyId, qx, qy);
    }

    function removePasskey(bytes32 keyId) external onlySelf {
        if (!passkeys[keyId].exists) revert PasskeyNotFound(keyId);
        delete passkeys[keyId];
        emit PasskeyRemoved(keyId);
    }

    /*//////////////////////////////////////////////////////////////
                               EXECUTE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute calls authorized by a WebAuthn passkey signature.
     *
     * @param keyId Which registered passkey is used.
     * @param authenticatorData Raw authenticatorData bytes from WebAuthn assertion.
     * @param clientDataJSONHash sha256(clientDataJSON) computed off-chain.
     * @param challengeHashProvided The challenge hash that was fed into WebAuthn (and shown to user).
     * @param r,s ECDSA(P-256) signature values (DER-decoded off-chain).
     * @param calls Batch calls to execute in the EOA context (via 7702 delegation).
     */
    function executeWebAuthn(
        bytes32 keyId,
        bytes calldata authenticatorData,
        bytes32 clientDataJSONHash,
        bytes32 challengeHashProvided,
        bytes32 r,
        bytes32 s,
        Call[] calldata calls
    ) external payable {
        Passkey memory pk = passkeys[keyId];
        if (!pk.exists) revert PasskeyNotFound(keyId);

        uint256 cur = nonce;

        // 1) Bind intent: compute expected challenge from exact payload.
        bytes32 callsHash = _hashCalls(calls);
        bytes32 expectedChallengeHash = _expectedChallengeHash(cur, callsHash);

        if (challengeHashProvided != expectedChallengeHash) {
            revert ChallengeMismatch(
                expectedChallengeHash,
                challengeHashProvided
            );
        }

        // 2) Verify WebAuthn signature:
        // signedBytesHash = sha256( authenticatorData || sha256(clientDataJSON) )
        bytes32 signedBytesHash = sha256(
            bytes.concat(authenticatorData, clientDataJSONHash)
        );

        if (!_p256Verify(signedBytesHash, r, s, pk.qx, pk.qy)) {
            revert InvalidPasskeySignature();
        }

        // bump nonce early
        nonce = cur + 1;

        // 3) Execute the batch.
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].to.call{
                value: calls[i].value
            }(calls[i].data);
            if (!ok) revert CallFailed(i, ret);
        }

        emit Executed(
            keyId,
            cur,
            expectedChallengeHash,
            signedBytesHash,
            calls.length
        );
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Compute expected challenge hash bound to (chainId, account, nonce, callsHash).
     * Client should use this as the WebAuthn challenge payload (e.g., base64url of these 32 bytes).
     */
    function expectedChallengeHash(
        Call[] calldata calls
    ) external view returns (bytes32) {
        return _expectedChallengeHash(nonce, _hashCalls(calls));
    }

    function _expectedChallengeHash(
        uint256 _nonce,
        bytes32 callsHash
    ) internal view returns (bytes32) {
        // sha256 over an unambiguous ABI encoding
        return
            sha256(
                abi.encode(
                    CHALLENGE_DOMAIN,
                    block.chainid,
                    address(this),
                    _nonce,
                    callsHash
                )
            );
    }

    function _hashCalls(Call[] calldata calls) internal pure returns (bytes32) {
        // Deterministic SHA-256 hashing:
        // perCall = sha256( to, value, sha256(data) )
        // callsHash = sha256( abi.encode(perCall[]) )
        bytes32[] memory per = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            per[i] = sha256(
                abi.encode(calls[i].to, calls[i].value, sha256(calls[i].data))
            );
        }
        return sha256(abi.encode(per));
    }

    function _p256Verify(
        bytes32 hash,
        bytes32 r,
        bytes32 s,
        bytes32 qx,
        bytes32 qy
    ) internal view returns (bool) {
        // Input: hash(32) || r(32) || s(32) || qx(32) || qy(32)
        bytes memory input = abi.encodePacked(hash, r, s, qx, qy);
        (bool ok, bytes memory out) = P256VERIFY.staticcall(input);
        if (!ok || out.length != 32) return false;
        return abi.decode(out, (uint256)) == 1;
    }

    receive() external payable {}
}
