<script lang="ts">
	import { onMount } from 'svelte';
	import {
		createPublicClient,
		createWalletClient,
		http,
		parseEther,
		encodeFunctionData,
		keccak256,
		toHex,
		toBytes,
		type Hex,
		type Address,
		sha256
	} from 'viem';
	import { privateKeyToAccount } from 'viem/accounts';
	import { sepolia } from 'viem/chains';
	import { decode } from 'cbor-x';
	import { p256 } from '@noble/curves/p256';

	// UI Components
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { Label } from '$lib/components/ui/label';

	import { CONTRACT_ABI } from '$lib/abi';

	// --- UTILS & ABI ---
	function findIndexOf(json: string, key: string): number {
		const index = json.indexOf(key);
		if (index === -1) return 0;
		return index;
	}

	function base64UrlToBytes(base64Url: string): Uint8Array {
		const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
		const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
		const rawData = atob(base64);
		return Uint8Array.from(rawData, (char) => char.charCodeAt(0));
	}

	function getPublicKeyFromAttestation(attestationObject: ArrayBuffer): { x: bigint; y: bigint } {
		const attObj = decode(new Uint8Array(attestationObject));
		addLog(`attestationObject: ${attObj}`);

		const authData = attObj.authData as Uint8Array;
		// get the length of the credential ID
		const dataView = new DataView(new ArrayBuffer(2));
		const idLenBytes = authData.slice(53, 55);
		idLenBytes.forEach((value, index) => dataView.setUint8(index, value));
		const credentialIdLength = dataView.getUint16(0);

		const credentialId = authData.slice(55, 55 + credentialIdLength);

		// get the public key object
		const publicKeyBytes = authData.slice(55 + credentialIdLength);

		// the publicKeyBytes are encoded again as CBOR
		const publicKeyObject = decode(new Uint8Array(publicKeyBytes.buffer));
		const x = publicKeyObject[-2];
		const y = publicKeyObject[-3];

		return { x: BigInt(toHex(x)), y: BigInt(toHex(y)) };
	}

	const chain = sepolia;

	type StoredCredential = { id: string; username: string; x: string; y: string; createdAt: number };

	let isLoading = false;
	let logs: string[] = [];
	let storedCredentials: StoredCredential[] = [];

	// --- State Variables ---
	// [Setup Mode]
	let manualPrivateKey: string = '';
	let implementationAddress: string = '';

	// [User Mode]
	let userWalletAddress: string = '';
	let relayerPrivateKey: string = '';

	// [Passkey State]
	let username: string = '';
	let currentCredentialId: string = '';
	let currentCredentialIdHash: string = '';
	let currentX: bigint = 0n;
	let currentY: bigint = 0n;

	// [Tx State]
	let toAddress: string = '';
	let ethValue: string = '0';
	let callData: string = '0x';

	function addLog(msg: string, type: 'info' | 'success' | 'error' = 'info') {
		const time = new Date().toLocaleTimeString('en-US', { hour12: false });
		const prefix = type === 'error' ? '[ERR]' : type === 'success' ? '[OK]' : '[INFO]';
		logs = [`${prefix} ${time} > ${msg}`, ...logs];
	}

	onMount(() => {
		const saved = localStorage.getItem('passkeys');
		if (saved) {
			try {
				storedCredentials = JSON.parse(saved);
				addLog(`Loaded ${storedCredentials.length} credentials.`);
			} catch (e) {}
		}
	});

	// --- Helpers ---
	function deriveAddressFromPK() {
		if (manualPrivateKey.length === 66 && manualPrivateKey.startsWith('0x')) {
			try {
				const account = privateKeyToAccount(manualPrivateKey as Hex);
				userWalletAddress = account.address; // Auto-sync to User Mode
				addLog(`Derived Address: ${userWalletAddress}`);
			} catch (e) {}
		}
	}

	async function registerNewCredential() {
		if (!username.trim()) return alert('Username required');
		try {
			isLoading = true;
			addLog(`Generating Passkey...`);
			const challenge = crypto.getRandomValues(new Uint8Array(32));

			const rpId = window.location.hostname;
			addLog(`rpId: ${rpId}`);

			const credential = (await navigator.credentials.create({
				publicKey: {
					challenge,
					rp: { name: 'WebAuthn Account', id: rpId },
					user: {
						id: crypto.getRandomValues(new Uint8Array(16)),
						name: username,
						displayName: username
					},
					pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
					authenticatorSelection: { userVerification: 'required' }
				}
			})) as PublicKeyCredential;

			const response = credential.response as AuthenticatorAttestationResponse;
			const { x, y } = getPublicKeyFromAttestation(response.attestationObject);
			currentCredentialId = credential.id;
			const bytes = base64UrlToBytes(credential.id);
			currentCredentialIdHash = keccak256(bytes);
			currentX = x;
			currentY = y;

			const newCred = {
				id: currentCredentialId,
				username,
				x: x.toString(16),
				y: y.toString(16),
				createdAt: Date.now()
			};
			if (!storedCredentials.some((c) => c.id === newCred.id)) {
				storedCredentials = [newCred, ...storedCredentials];
				localStorage.setItem('passkeys', JSON.stringify(storedCredentials));
			}

			addLog(`Passkey Created! Ready to Register.`, 'success');
		} catch (e: any) {
			console.error(e);
			addLog(`Error: ${e.message}`, 'error');
		} finally {
			isLoading = false;
		}
	}

	async function upgradeEOA() {
		if (!implementationAddress.startsWith('0x')) return alert('Contract Address required');
		if (!manualPrivateKey) return alert('Private Key required');
		try {
			isLoading = true;
			const localAccount = privateKeyToAccount(manualPrivateKey as Hex);
			const signerClient = createWalletClient({
				account: localAccount,
				chain: sepolia,
				transport: http()
			});

			addLog(`Signing EIP-7702 Authorization...`);
			const authorization = await signerClient.signAuthorization({
				contractAddress: implementationAddress as Address,
				executor: 'self'
			});

			addLog(`Broadcasting Upgrade EOA Tx...`);
			const hash = await signerClient.sendTransaction({
				to: localAccount.address,
				value: 0n,
				data: '0x',
				authorizationList: [authorization]
			});
			addLog(`Upgrade Successful: ${hash}`, 'success');
		} catch (e: any) {
			console.error(e);
			addLog(`Error: ${e.message}`, 'error');
		} finally {
			isLoading = false;
		}
	}

	async function registerPasskeyOnChain() {
		if (!currentCredentialId) return alert('Generate a Passkey first');
		if (!manualPrivateKey) return alert('Private Key required');
		try {
			isLoading = true;
			const localAccount = privateKeyToAccount(manualPrivateKey as Hex);
			const signerClient = createWalletClient({
				account: localAccount,
				chain: sepolia,
				transport: http()
			});

			addLog('Registering Key on-chain...');
			const credIdBytes = base64UrlToBytes(currentCredentialId);
			const credIdHash = keccak256(credIdBytes);

			const hash = await signerClient.writeContract({
				address: localAccount.address,
				abi: CONTRACT_ABI,
				functionName: 'setKey',
				args: [credIdHash, currentX, currentY, true]
			});
			addLog(`Key Registered: ${hash}`, 'success');
		} catch (e: any) {
			console.error(e);
			addLog(`Error: ${e.message}`, 'error');
		} finally {
			isLoading = false;
		}
	}

	function selectCredential(cred: StoredCredential) {
		currentCredentialId = cred.id;
		username = cred.username;
		currentX = BigInt('0x' + cred.x);
		currentY = BigInt('0x' + cred.y);
		const bytes = base64UrlToBytes(cred.id);
		currentCredentialIdHash = keccak256(bytes);
		addLog(`Identity Loaded: ${cred.username}`, 'success');
	}

	// --- Step 4: Execute (UserOp) ---
	async function sendUserOperation() {
		if (!currentCredentialId) return alert('Select a Passkey');
		if (!userWalletAddress || !userWalletAddress.startsWith('0x'))
			return alert('Target Wallet Address required');

		if (!relayerPrivateKey || relayerPrivateKey.length !== 66) {
			return alert('Relayer Private Key required');
		}

		try {
			isLoading = true;

			const account = privateKeyToAccount(relayerPrivateKey as Hex);
			const senderAddress = account.address;
			const senderClient = createWalletClient({ account, chain: sepolia, transport: http() });
			const publicClient = createPublicClient({ chain, transport: http() });
			const targetEOA = userWalletAddress as Address;

			addLog(`Using Local Relayer: ${senderAddress}...`);
			addLog('Preparing Transaction...');

			const internalTo = toAddress as Address;
			const internalValue = parseEther(ethValue);
			const internalData = callData as Hex;
			const currentCredIdBytes = base64UrlToBytes(currentCredentialId);
			const credentialIdHash = keccak256(currentCredIdBytes);

			const nonce = await publicClient.readContract({
				address: targetEOA,
				abi: CONTRACT_ABI,
				functionName: 'nonces',
				args: [credentialIdHash]
			});
			const deadline = BigInt(9999999999);
			const challengeHash = await publicClient.readContract({
				address: targetEOA,
				abi: CONTRACT_ABI,
				functionName: 'challengeExecute',
				args: [
					targetEOA,
					credentialIdHash,
					internalTo,
					internalValue,
					nonce,
					internalData,
					deadline
				]
			});
			addLog(`challenge: ${challengeHash}`);
			addLog(`Requesting Biometric Auth...`);

			const assertion = (await navigator.credentials.get({
				publicKey: {
					challenge: toBytes(challengeHash).buffer as ArrayBuffer,
					allowCredentials: [{ id: currentCredIdBytes.buffer as ArrayBuffer, type: 'public-key' }],
					userVerification: 'required'
				}
			})) as PublicKeyCredential;

			const response = assertion.response as AuthenticatorAssertionResponse;
			const { r, s } = p256.Signature.fromDER(new Uint8Array(response.signature)).normalizeS();
			addLog(`signature: ${toHex(r)}, ${toHex(s)}`);

			const clientDataJSON = new TextDecoder().decode(response.clientDataJSON);
			addLog(`clientDataJSON: ${clientDataJSON}`);

			const challengeIndex = findIndexOf(clientDataJSON, '"challenge":"');
			const typeIndex = findIndexOf(clientDataJSON, '"type":"webauthn.get"');

			addLog(`challengeIndex: ${challengeIndex}`);
			addLog(`typeIndex: ${typeIndex}`);

			addLog(`Broadcasting...`);

			const authenticatorDataBytes = new Uint8Array(response.authenticatorData);
			const authenticatorData = toHex(authenticatorDataBytes);
			addLog(`authenticatorData: ${authenticatorData}`);

			const clientDataJSONBytes = new TextEncoder().encode(clientDataJSON);
			const clientDataHash = toBytes(sha256(clientDataJSONBytes));

			const signedData = new Uint8Array(authenticatorDataBytes.length + clientDataHash.length);
			signedData.set(authenticatorDataBytes, 0);
			signedData.set(clientDataHash, authenticatorDataBytes.length);

			const messageHash = sha256(signedData);
			addLog(`messageHash: ${messageHash}`);

			const txData = encodeFunctionData({
				abi: CONTRACT_ABI,
				functionName: 'execute',
				args: [
					credentialIdHash,
					internalTo,
					internalValue,
					internalData,
					deadline,
					{
						authenticatorData,
						clientDataJSON: clientDataJSON,
						challengeIndex: challengeIndex,
						typeIndex: typeIndex,
						userVerificationRequired: true
					},
					{ r, s }
				]
			});

			addLog(`Running Simulation (call)...`);
			try {
				await publicClient.call({
					to: targetEOA,
					data: txData,
					value: 0n
				});

				addLog(`Simulation ✅ Passed!`, 'success');
			} catch (simError: any) {
				console.error('Simulation Failed:', simError);

				const errorMsg = simError.shortMessage || simError.message || 'Unknown Revert';
				addLog(`Simulation ❌ FAILED: ${errorMsg}`, 'error');

				if (
					!confirm(
						`Simulation failed with error:\n"${errorMsg}"\n\nDo you want to force send anyway?`
					)
				) {
					return;
				}
			}

			const hash = await senderClient.sendTransaction({
				to: targetEOA,
				data: txData,
				value: 0n,
				chain: sepolia
			});

			addLog(`Transaction Executed! Hash: ${hash}`, 'success');
		} catch (e: any) {
			console.error(e);
			const errMsg = e.message.length > 100 ? e.message.slice(0, 100) + '...' : e.message;
			addLog(`Error: ${errMsg}`, 'error');
		} finally {
			isLoading = false;
		}
	}
</script>

<div class="flex h-screen w-screen overflow-hidden bg-white font-mono text-black">
	<div class="flex h-full min-w-0 flex-1 flex-col border-r-2 border-black">
		<header
			class="z-10 flex h-16 items-center justify-between border-b-2 border-black bg-white px-6"
		>
			<div class="flex items-center gap-2">
				<div class="h-4 w-4 bg-black"></div>
				<h1 class="text-lg font-bold tracking-tighter uppercase">WebAuthn_Account</h1>
			</div>
			<div class="flex items-center gap-2">
				<Badge variant="outline" class="rounded-none border-black text-black">SEPOLIA</Badge>
			</div>
		</header>

		<div class="flex flex-1 flex-col gap-4 overflow-y-auto bg-gray-50/50 p-6 md:p-10">
			<Card class="rounded-none border-2 border-black shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
				<CardHeader>
					<CardTitle>1. EOA Upgrade</CardTitle>
				</CardHeader>
				<CardContent class="space-y-4">
					<div class="space-y-2">
						<Label>Private Key</Label>
						<Input
							type="password"
							bind:value={manualPrivateKey}
							oninput={deriveAddressFromPK}
							placeholder="0x..."
							class="rounded-none border-black"
						/>
					</div>
					<div class="space-y-2">
						<Label>Smart Account</Label>
						<Input
							bind:value={implementationAddress}
							placeholder="Contract Address (0x...)"
							class="rounded-none border-black"
						/>
					</div>
					<Button
						onclick={upgradeEOA}
						disabled={isLoading || !manualPrivateKey || !implementationAddress}
						class="w-full rounded-none border-2 border-black bg-black font-bold text-white hover:bg-gray-800"
					>
						Upgrade EOA
					</Button>
				</CardContent>
			</Card>

			<Card class="rounded-none border-2 border-black shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
				<CardHeader>
					<CardTitle>2. Generate Passkey</CardTitle>
				</CardHeader>
				<CardContent class="space-y-4">
					<div class="space-y-2">
						<Label>Passkey Username</Label>
						<div class="flex gap-2">
							<Input
								bind:value={username}
								placeholder="e.g. MyPasskey"
								class="rounded-none border-black"
							/>
							<Button
								onclick={registerNewCredential}
								disabled={isLoading}
								class="rounded-none bg-black text-white hover:bg-gray-800"
							>
								Generate
							</Button>
						</div>
					</div>
				</CardContent>
			</Card>

			<Card class="rounded-none border-2 border-black shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
				<CardHeader>
					<CardTitle>3. Register Passkey</CardTitle>
				</CardHeader>
				<CardContent class="space-y-4">
					<div class="space-y-2">
						<Label>Private Key</Label>
						<Input
							type="password"
							bind:value={manualPrivateKey}
							oninput={deriveAddressFromPK}
							placeholder="0x..."
							class="rounded-none border-black"
						/>
					</div>
					<div class="space-y-2">
						<Label>Saved Passkeys</Label>
						<div class="grid grid-cols-1 gap-2">
							{#each storedCredentials as cred}
								<button
									onclick={() => selectCredential(cred)}
									class="flex items-center justify-between border bg-white p-3 transition-all hover:bg-gray-50 {currentCredentialId ===
									cred.id
										? 'bg-green-50 ring-2 ring-black'
										: ''}"
								>
									<div class="text-left">
										<div class="text-sm font-bold">{cred.username}</div>
										<div class="text-[10px] text-gray-500">
											ID: {cred.id}
										</div>
									</div>
									{#if currentCredentialId === cred.id}<Badge class="rounded-none bg-green-600"
											>ACTIVE</Badge
										>{/if}
								</button>
							{/each}
							{#if storedCredentials.length === 0}
								<div class="border border-dashed py-4 text-center text-sm text-gray-400">
									No saved keys. Go to Setup tab.
								</div>
							{/if}
						</div>

						{#if currentCredentialId}
							<div class="mt-4 border-t border-dashed pt-4">
								<div class="space-y-2 border border-black/10 bg-gray-100 p-3">
									<Label class="text-[10px] font-bold text-gray-500 uppercase">
										Selected Key Details
									</Label>
									<div class="flex flex-col gap-1 text-[10px] text-gray-600">
										<div class="flex flex-col">
											<span class="font-bold text-black">Cred ID Hash (On-chain Key):</span>
											<span class="break-all">{currentCredentialIdHash}</span>
										</div>
										<div class="mt-1 flex flex-col">
											<span class="font-bold text-black">Public Key:</span>
											<span class="break-all">X: 0x{currentX.toString(16)}</span>
											<span class="break-all">Y: 0x{currentY.toString(16)}</span>
										</div>
									</div>
								</div>
							</div>
						{/if}
					</div>
					<Button
						onclick={registerPasskeyOnChain}
						disabled={isLoading || !manualPrivateKey || !currentCredentialId}
						class="w-full rounded-none border-2 border-black bg-black font-bold text-white hover:bg-gray-800"
					>
						Register Key
					</Button>
				</CardContent>
			</Card>

			<Card class="rounded-none border-2 border-black shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
				<CardHeader>
					<CardTitle>4. Send Transaction</CardTitle>
				</CardHeader>
				<CardContent>
					<div class="space-y-4">
						<div class="space-y-2">
							<Label>Relayer Private Key</Label>
							<Input
								type="password"
								bind:value={relayerPrivateKey}
								placeholder="0x..."
								class="mt-1 h-8 rounded-none border-black text-xs"
							/>
						</div>
						<div class="space-y-2">
							<Label>Target Address</Label>
							<Input
								bind:value={userWalletAddress}
								placeholder="0x..."
								class="rounded-none border-black"
							/>
						</div>
						<div class="space-y-2">
							<Label>Saved Passkeys</Label>
							<div class="grid grid-cols-1 gap-2">
								{#each storedCredentials as cred}
									<button
										onclick={() => selectCredential(cred)}
										class="flex items-center justify-between border bg-white p-3 transition-all hover:bg-gray-50 {currentCredentialId ===
										cred.id
											? 'bg-green-50 ring-2 ring-black'
											: ''}"
									>
										<div class="text-left">
											<div class="text-sm font-bold">{cred.username}</div>
											<div class="text-[10px] text-gray-500">
												ID: {cred.id}
											</div>
										</div>
										{#if currentCredentialId === cred.id}
											<Badge class="rounded-none bg-green-600">ACTIVE</Badge>{/if}
									</button>
								{/each}
								{#if storedCredentials.length === 0}
									<div class="border border-dashed py-4 text-center text-sm text-gray-400">
										No saved keys. Go to Generate Passkey.
									</div>
								{/if}
							</div>

							{#if currentCredentialId}
								<div class="mt-4 border-t border-dashed pt-4">
									<div class="space-y-2 border border-black/10 bg-gray-100 p-3">
										<Label class="text-[10px] font-bold text-gray-500 uppercase">
											Selected Key Details
										</Label>
										<div class="flex flex-col gap-1 text-[10px] text-gray-600">
											<div class="flex flex-col">
												<span class="font-bold text-black">Cred ID Hash (On-chain Key):</span>
												<span class="break-all">{currentCredentialIdHash}</span>
											</div>
											<div class="mt-1 flex flex-col">
												<span class="font-bold text-black">Public Key:</span>
												<span class="break-all">X: 0x{currentX.toString(16)}</span>
												<span class="break-all">Y: 0x{currentY.toString(16)}</span>
											</div>
										</div>
									</div>
								</div>
							{/if}
						</div>
						<div class="grid grid-cols-2 gap-4">
							<div class="space-y-2">
								<Label>To Address</Label>
								<Input
									bind:value={toAddress}
									placeholder="0x..."
									class="rounded-none border-black"
								/>
							</div>
							<div class="space-y-2">
								<Label>Value (ETH)</Label>
								<Input bind:value={ethValue} placeholder="0.0" class="rounded-none border-black" />
							</div>
						</div>
						<div class="space-y-2">
							<Label>Call Data</Label>
							<Input bind:value={callData} placeholder="0x" class="rounded-none border-black" />
						</div>
						<Button
							onclick={sendUserOperation}
							disabled={isLoading ||
								!relayerPrivateKey ||
								!userWalletAddress ||
								!currentCredentialId}
							class="w-full rounded-none border-2 border-black bg-black font-bold text-white hover:bg-gray-800"
						>
							{isLoading ? 'Processing...' : 'Sign & Send'}
						</Button>
					</div>
				</CardContent>
			</Card>
		</div>
	</div>

	<div class="hidden w-[400px] flex-col border-l border-gray-800 bg-black text-white lg:flex">
		<div class="flex h-16 items-center justify-between border-b border-gray-800 px-4">
			<span class="flex items-center gap-2 text-xs font-bold tracking-widest uppercase"
				><span class="h-2 w-2 animate-pulse rounded-full bg-green-500"></span>Terminal</span
			>
			<button
				onclick={() => (logs = [])}
				class="text-[10px] text-gray-500 uppercase hover:text-white">Clear</button
			>
		</div>
		<div class="flex-1 space-y-2 overflow-y-auto p-4 text-xs">
			{#if logs.length === 0}<div class="mt-4 text-gray-600 italic">
					> Waiting for commands...
				</div>{/if}
			{#each logs as log}<div
					class="border-l-2 border-transparent pl-2 leading-relaxed break-all opacity-90 transition-colors hover:border-gray-500"
				>
					{log}
				</div>{/each}
		</div>
	</div>
</div>
