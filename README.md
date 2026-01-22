# Passkey WebAuthn Account PoC (EIP-7702 + EIP-7951)

PoC implementation of an **EOA upgrade** (via **EIP-7702 SetCode/delegation**) into a **WebAuthn Passkey-controlled account**, with on-chain **P-256 (secp256r1)** verification enabled by **EIP-7951**.

---

## Flow

### 1) Upgrade EOA (EIP-7702)

Delegate the EOA to a deployed `WebAuthnAccount` contract.

```ts
const authorization = await signerClient.signAuthorization({
  contractAddress: webAuthnContract as Address,
  executor: "self",
});

await signerClient.sendTransaction({
  to: localAccount.address,
  value: 0n,
  data: "0x",
  authorizationList: [authorization],
});
```

### 2) Create & Register Passkey

Create a Passkey with WebAuthn and register its public key on-chain using `credIdHash = keccak256(credentialId)`.

```ts
const credential = (await navigator.credentials.create({
  publicKey: {
    challenge,
    rp: { name: "WebAuthn Account", id: rpId },
    user: {
      id: crypto.getRandomValues(new Uint8Array(16)),
      name: username,
      displayName: username,
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    authenticatorSelection: { userVerification: "required" },
  },
})) as PublicKeyCredential;

await signerClient.writeContract({
  address: localAccount.address,
  abi: CONTRACT_ABI,
  functionName: "setKey",
  args: [credIdHash, x, y, true],
});
```

### 3) Sign Operation & Execute (Relayed)

Derive a deterministic challenge from operation fields, sign it via WebAuthn assertion, and send `execute()` to the upgraded EOA.

```ts
const assertion = (await navigator.credentials.get({
  publicKey: {
    challenge: toBytes(derivedChallenge).buffer as ArrayBuffer,
    allowCredentials: [
      { id: credIdBytes.buffer as ArrayBuffer, type: "public-key" },
    ],
    userVerification: "required",
  },
})) as PublicKeyCredential;

const txData = encodeFunctionData({
  abi: CONTRACT_ABI,
  functionName: "execute",
  args: [
    credentialIdHash,
    to,
    value,
    data,
    deadline,
    {
      authenticatorData,
      clientDataJSON,
      challengeIndex,
      typeIndex,
      userVerificationRequired: true,
    },
    { r, s },
  ],
});

await relayerClient.sendTransaction({
  to: targetEOA,
  data: txData,
  value: 0n,
});
```

---

## Contract Summary

- `setKey`: register/enable/disable Passkey public keys by `credIdHash`
- `_verifyExecute`: verify WebAuthn(P-256) signature for the derived challenge
- `execute`: validate signature, update nonce, and perform the call

WebAuthn P-256 verification is based on Ithaca `exp-0001` implementation.

---

## Notes

- WebAuthn uses **SHA-256** + **secp256r1 (P-256)**
- EIP-7951 provides an on-chain P-256 precompile (address differs by fork/network)
- This repo is a **PoC**, not production hardened

---

## References

- WebAuthn / Passkeys
- EIP-7702 (EOA delegation)
- EIP-7951 (secp256r1 precompile)
- Ithaca `exp-0001` WebAuthnP256.sol
