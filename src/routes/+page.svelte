<script lang="ts">
	import { onMount } from 'svelte';
	import {
		createPublicClient,
		createWalletClient,
		http,
		custom,
		parseEther,
		encodeFunctionData,
		keccak256,
		toHex,
		toBytes,
		type Hex,
		type Address
	} from 'viem';
	import { privateKeyToAccount } from 'viem/accounts';
	import { sepolia } from 'viem/chains';
	import { decode } from 'cbor-x';
	import { fromBER, Sequence, Integer } from 'asn1js';

	// UI Components
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import {
		Card,
		CardContent,
		CardHeader,
		CardTitle,
		CardDescription
	} from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { Tabs, TabsContent, TabsList, TabsTrigger } from '$lib/components/ui/tabs';
	import { Label } from '$lib/components/ui/label';
	import { Separator } from '$lib/components/ui/separator';

	// --- UTILS & ABI ---
	function findIndexOf(json: string, key: string): number {
		const keyPattern = `"${key}":"`;
		const index = json.indexOf(keyPattern);
		if (index === -1) return 0;
		return index + keyPattern.length;
	}

	function base64UrlToBytes(base64Url: string): Uint8Array {
		const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
		const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
		const rawData = atob(base64);
		return Uint8Array.from(rawData, (char) => char.charCodeAt(0));
	}

	function getPublicKeyFromAttestation(attestationObject: ArrayBuffer): { x: bigint; y: bigint } {
		const attObj = decode(new Uint8Array(attestationObject));
		const authData = attObj.authData as Uint8Array;
		const dataView = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
		let offset = 37;
		offset += 16;
		const credIdLen = dataView.getUint16(offset);
		offset += 2;
		offset += credIdLen;
		const coseKeyBuffer = authData.subarray(offset);
		const coseKey = decode(coseKeyBuffer);
		const x = coseKey instanceof Map ? coseKey.get(-2) : coseKey[-2];
		const y = coseKey instanceof Map ? coseKey.get(-3) : coseKey[-3];
		if (!x || !y) throw new Error('Invalid COSE Key: Missing coordinates');
		return { x: BigInt(toHex(x)), y: BigInt(toHex(y)) };
	}

	function parseDERSignature(signature: ArrayBuffer) {
		const { result } = fromBER(signature);
		if (!(result instanceof Sequence)) throw new Error('Invalid DER signature');
		const rBlock = result.valueBlock.value[0];
		const sBlock = result.valueBlock.value[1];
		if (!(rBlock instanceof Integer) || !(sBlock instanceof Integer))
			throw new Error('Invalid DER signature');
		return {
			r: BigInt(toHex(rBlock.valueBlock.valueHexView)),
			s: BigInt(toHex(sBlock.valueBlock.valueHexView))
		};
	}

	const CONTRACT_ABI = [
		{
			type: 'function',
			name: 'execute',
			inputs: [
				{ name: 'credentialIdHash', type: 'bytes32' },
				{ name: 'to', type: 'address' },
				{ name: 'value', type: 'uint256' },
				{ name: 'data', type: 'bytes' },
				{ name: 'deadline', type: 'uint256' },
				{
					name: 'metadata',
					type: 'tuple',
					components: [
						{ name: 'authenticatorData', type: 'bytes' },
						{ name: 'clientDataJSON', type: 'string' },
						{ name: 'challengeIndex', type: 'uint16' },
						{ name: 'typeIndex', type: 'uint16' },
						{ name: 'userVerificationRequired', type: 'bool' }
					]
				},
				{
					name: 'signature',
					type: 'tuple',
					components: [
						{ name: 'r', type: 'uint256' },
						{ name: 's', type: 'uint256' }
					]
				}
			],
			outputs: [{ name: 'result', type: 'bytes' }],
			stateMutability: 'payable'
		},
		{
			type: 'function',
			name: 'setKey',
			inputs: [
				{ name: 'credentialIdHash', type: 'bytes32' },
				{ name: 'x', type: 'uint256' },
				{ name: 'y', type: 'uint256' },
				{ name: 'enabled', type: 'bool' }
			],
			outputs: [],
			stateMutability: 'nonpayable'
		},
		{
			type: 'function',
			name: 'nonces',
			inputs: [{ name: '', type: 'bytes32' }],
			outputs: [{ name: '', type: 'uint256' }],
			stateMutability: 'view'
		},
		{
			type: 'function',
			name: 'challengeExecute',
			inputs: [
				{ name: 'credentialIdHash', type: 'bytes32' },
				{ name: 'to', type: 'address' },
				{ name: 'value', type: 'uint256' },
				{ name: 'nonce', type: 'uint256' },
				{ name: 'data', type: 'bytes' },
				{ name: 'deadline', type: 'uint256' }
			],
			outputs: [{ name: '', type: 'bytes32' }],
			stateMutability: 'view'
		},
		{
			type: 'function',
			name: 'keys',
			inputs: [{ name: '', type: 'bytes32' }],
			outputs: [
				{ name: 'x', type: 'uint256' },
				{ name: 'y', type: 'uint256' },
				{ name: 'enabled', type: 'bool' }
			],
			stateMutability: 'view'
		}
	] as const;

	const chain = sepolia;

	type StoredCredential = { id: string; username: string; x: string; y: string; createdAt: number };

	let clientAddress: Address | undefined;
	let isLoading = false;
	let logs: string[] = [];
	let storedCredentials: StoredCredential[] = [];

	// --- State Variables ---
	// [Setup Mode]
	let manualPrivateKey: string = '';
	let implementationAddress: string = '';

	// [User Mode]
	let userWalletAddress: string = '';
	let relayerPrivateKey: string = ''; // [Preserved] Relayer PK for Execution

	// [Passkey State]
	let username: string = '';
	let currentCredentialId: string = '';
	let currentCredentialIdHash: string = '';
	let currentX: bigint = 0n;
	let currentY: bigint = 0n;

	// [Tx State]
	let targetAddress: string = '';
	let ethValue: string = '0';
	let callData: string = '0x';

	let debugLog: string = '';

	function addLog(msg: string, type: 'info' | 'success' | 'error' = 'info') {
		const time = new Date().toLocaleTimeString('en-US', { hour12: false });
		const prefix = type === 'error' ? '[ERR]' : type === 'success' ? '[OK]' : '[INFO]';
		logs = [`${prefix} ${time} > ${msg}`, ...logs];
	}

	onMount(() => {
		const saved = localStorage.getItem('webauthn_keys');
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

	async function getBrowserClient() {
		if (!window.ethereum) throw new Error('No wallet found');
		const walletClient = createWalletClient({ chain, transport: custom(window.ethereum) });
		const [address] = await walletClient.requestAddresses();
		clientAddress = address;
		return { walletClient, address };
	}

	// --- Actions ---

	async function registerNewCredential() {
		if (!username.trim()) return alert('Username required');
		try {
			isLoading = true;
			addLog(`Generating Passkey...`);
			const challenge = crypto.getRandomValues(new Uint8Array(32));
			const rpId = window.location.hostname;
			const credential = (await navigator.credentials.create({
				publicKey: {
					challenge,
					rp: { name: 'WebAuthn 7702 Wallet', id: rpId },
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
				localStorage.setItem('webauthn_keys', JSON.stringify(storedCredentials));
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

			addLog(`Signing 7702 Authorization...`);
			const authorization = await signerClient.signAuthorization({
				contractAddress: implementationAddress as Address
			});

			const { walletClient: senderClient, address: senderAddress } = await getBrowserClient();
			addLog(`Broadcasting Upgrade Tx...`);
			const hash = await senderClient.sendTransaction({
				to: localAccount.address,
				value: 0n,
				data: '0x',
				authorizationList: [authorization],
				account: senderAddress
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
		if (!currentCredentialId) return alert('Select a Passkey (Login)');
		if (!userWalletAddress || !userWalletAddress.startsWith('0x'))
			return alert('Target Wallet Address required');

		if (!relayerPrivateKey || relayerPrivateKey.length !== 66) {
			return alert('Relayer Private Key required');
		}

		try {
			isLoading = true;

			// 1. Relayer 설정
			const account = privateKeyToAccount(relayerPrivateKey as Hex);
			const senderAddress = account.address;
			const senderClient = createWalletClient({ account, chain: sepolia, transport: http() });
			const publicClient = createPublicClient({ chain, transport: http() });
			const targetEOA = userWalletAddress as Address;

			addLog(`Using Local Relayer: ${senderAddress.slice(0, 6)}...`);
			addLog('Preparing Transaction...');

			const internalTo = targetAddress as Address;
			const internalValue = parseEther(ethValue);
			const internalData = callData as Hex;
			const currentCredIdBytes = base64UrlToBytes(currentCredentialId);
			const credentialIdHash = keccak256(currentCredIdBytes);

			// 2. Read Nonce & Challenge
			const nonce = await publicClient.readContract({
				address: targetEOA,
				abi: CONTRACT_ABI,
				functionName: 'nonces',
				args: [credentialIdHash]
			});
			const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
			const challengeHash = await publicClient.readContract({
				address: targetEOA,
				abi: CONTRACT_ABI,
				functionName: 'challengeExecute',
				args: [credentialIdHash, internalTo, internalValue, nonce, internalData, deadline]
			});
			addLog(`challenge: ${challengeHash}`);
			addLog(`Requesting Biometric Auth...`);

			// 3. WebAuthn Sign
			const assertion = (await navigator.credentials.get({
				publicKey: {
					challenge: toBytes(challengeHash).buffer as ArrayBuffer,
					allowCredentials: [{ id: currentCredIdBytes.buffer as ArrayBuffer, type: 'public-key' }],
					userVerification: 'required'
				}
			})) as PublicKeyCredential;

			const response = assertion.response as AuthenticatorAssertionResponse;
			const { r, s } = parseDERSignature(response.signature);
			const clientDataJSON = new TextDecoder().decode(response.clientDataJSON);
			const challengeIndex = findIndexOf(clientDataJSON, 'challenge');
			const typeIndex = findIndexOf(clientDataJSON, 'type');

			addLog(`Broadcasting...`);

			// 4. Encode Data
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
						authenticatorData: toHex(new Uint8Array(response.authenticatorData)),
						clientDataJSON: clientDataJSON,
						challengeIndex: challengeIndex,
						typeIndex: typeIndex,
						userVerificationRequired: true
					},
					{ r, s }
				]
			});

			// ---------------------------------------------------------
			// ★ [Step 8] Pre-flight Simulation (publicClient.call)
			// ---------------------------------------------------------
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

				// 에러 메시지 분석 (Revert Reason 찾기)
				const errorMsg = simError.shortMessage || simError.message || 'Unknown Revert';
				addLog(`Simulation ❌ FAILED: ${errorMsg}`, 'error');

				// 시뮬레이션 실패 시 진행 여부 묻기
				if (
					!confirm(
						`Simulation failed with error:\n"${errorMsg}"\n\nDo you want to force send anyway?`
					)
				) {
					return; // 취소하면 여기서 중단
				}
			}
			// ---------------------------------------------------------

			// 5. Send Raw Transaction
			const hash = await senderClient.sendTransaction({
				to: targetEOA,
				data: txData,
				value: 0n,
				chain: sepolia,
				account
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

	async function debugContractState() {
		if (!userWalletAddress) return alert('Target Address required');
		if (!currentCredentialId) return alert('Select a Credential first');

		try {
			const publicClient = createPublicClient({ chain, transport: http() });
			const targetEOA = userWalletAddress as Address;

			// 1. 코드 존재 여부 (Upgrade 확인)
			const code = await publicClient.getBytecode({ address: targetEOA });
			const hasCode = code && code !== '0x';

			// 2. 키 등록 여부 확인
			const credIdBytes = base64UrlToBytes(currentCredentialId);
			const credIdHash = keccak256(credIdBytes);

			let keyInfo = { x: 0n, y: 0n, enabled: false };
			try {
				// keys 매핑 조회
				const [x, y, enabled] = (await publicClient.readContract({
					address: targetEOA,
					abi: CONTRACT_ABI,
					functionName: 'keys',
					args: [credIdHash]
				})) as [bigint, bigint, boolean];
				keyInfo = { x, y, enabled };
			} catch (e) {
				console.error('Key read failed (Contract might not be upgraded)');
			}

			// 3. Nonce 확인
			const nonce = await publicClient.readContract({
				address: targetEOA,
				abi: CONTRACT_ABI,
				functionName: 'nonces',
				args: [credIdHash]
			});

			// 결과 출력
			let report = `=== 🐞 Debug Report ===\n`;
			report += `Target: ${targetEOA.slice(0, 10)}...\n`;
			report += `1. Contract Upgraded: ${hasCode ? '✅ YES' : '❌ NO (Code Missing)'}\n`;
			report += `2. Key Registered: ${keyInfo.enabled ? '✅ YES' : '❌ NO'}\n`;
			if (keyInfo.enabled) {
				report += `   On-Chain X: ${keyInfo.x.toString(16).slice(0, 10)}...\n`;
				report += `   Local    X: ${currentX.toString(16).slice(0, 10)}...\n`;
				report += `   Match: ${keyInfo.x === currentX ? '✅' : '❌ MISMATCH'}\n`;
			}
			report += `3. Current Nonce: ${nonce}\n`;

			alert(report); // 간편하게 Alert로 리포트 표시
			console.log(report);
		} catch (e: any) {
			alert(`Debug Error: ${e.message}`);
		}
	}
</script>

<div class="flex h-screen w-screen overflow-hidden bg-white font-sans text-black">
	<div class="flex h-full min-w-0 flex-1 flex-col border-r-2 border-black">
		<header
			class="z-10 flex h-16 items-center justify-between border-b-2 border-black bg-white px-6"
		>
			<div class="flex items-center gap-2">
				<div class="h-4 w-4 bg-black"></div>
				<h1 class="text-lg font-bold tracking-tighter uppercase">WebAuthn.7702</h1>
			</div>
			<div class="flex items-center gap-2">
				<Badge variant="outline" class="rounded-none border-black text-black">SEPOLIA</Badge>
				{#if clientAddress}<span
						class="hidden bg-gray-100 px-2 py-1 font-mono text-xs md:inline-block"
						>Relayer: {clientAddress.slice(0, 6)}...</span
					>{/if}
			</div>
		</header>

		<div class="flex-1 overflow-y-auto bg-gray-50/50 p-6 md:p-10">
			<Tabs value="setup" class="mx-auto w-full max-w-3xl space-y-6">
				<TabsList class="grid w-full grid-cols-2 rounded-none bg-black p-1">
					<TabsTrigger
						value="setup"
						class="rounded-none font-bold tracking-wider text-white uppercase data-[state=active]:bg-white data-[state=active]:text-black"
					>
						⚙️ Initialize (Admin)
					</TabsTrigger>
					<TabsTrigger
						value="use"
						class="rounded-none font-bold tracking-wider text-white uppercase data-[state=active]:bg-white data-[state=active]:text-black"
					>
						🚀 Transact (User)
					</TabsTrigger>
				</TabsList>

				<TabsContent value="setup" class="space-y-6">
					<Card class="rounded-none border-2 border-black shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
						<CardHeader>
							<CardTitle>1. Target Wallet Setup</CardTitle>
							<CardDescription
								>Enter the Private Key of the EOA you want to upgrade.</CardDescription
							>
						</CardHeader>
						<CardContent class="space-y-4">
							<div class="space-y-2">
								<Label>Target Private Key</Label>
								<Input
									type="password"
									bind:value={manualPrivateKey}
									oninput={deriveAddressFromPK}
									placeholder="0x..."
									class="rounded-none border-black font-mono"
								/>
							</div>
							{#if userWalletAddress}
								<div class="flex justify-between border bg-gray-100 p-2 font-mono text-xs">
									<span>Target: {userWalletAddress}</span>
									<Badge class="rounded-none bg-green-600">VALID</Badge>
								</div>
							{/if}
						</CardContent>
					</Card>

					<Card
						class="rounded-none border-2 border-black shadow-[4px_4px_0px_0px_rgba(0,0,0,1)] {!userWalletAddress
							? 'pointer-events-none opacity-50'
							: ''}"
					>
						<CardHeader>
							<CardTitle>2. Identity & Contract</CardTitle>
							<CardDescription>Generate a Passkey and upgrade the account.</CardDescription>
						</CardHeader>
						<CardContent class="space-y-6">
							<div class="space-y-2">
								<Label>New Passkey Username</Label>
								<div class="flex gap-2">
									<Input
										bind:value={username}
										placeholder="e.g. MyFaceID"
										class="rounded-none border-black"
									/>
									<Button
										onclick={registerNewCredential}
										disabled={isLoading}
										class="rounded-none bg-black text-white hover:bg-gray-800">Generate</Button
									>
								</div>
								{#if currentCredentialId}
									<div class="mt-1 font-mono text-[10px] text-green-600">
										✓ Generated: {currentCredentialId.slice(0, 20)}...
									</div>
								{/if}
							</div>
							<Separator />
							<div class="space-y-2">
								<Label>Smart Account Setup</Label>
								<div class="flex gap-2">
									<Input
										bind:value={implementationAddress}
										placeholder="Contract Address (0x...)"
										class="flex-1 rounded-none border-black font-mono text-xs"
									/>
								</div>
								<div class="mt-2 flex gap-2">
									<Button
										onclick={upgradeEOA}
										disabled={isLoading}
										class="flex-1 rounded-none border-2 border-black bg-white font-bold text-black hover:bg-gray-100"
										>A. Upgrade Code</Button
									>
									<Button
										onclick={registerPasskeyOnChain}
										disabled={isLoading || !currentCredentialId}
										class="flex-1 rounded-none border-2 border-black bg-black font-bold text-white hover:bg-gray-800"
										>B. Register Key</Button
									>
								</div>
							</div>
						</CardContent>
					</Card>
				</TabsContent>

				<TabsContent value="use" class="space-y-6">
					<Card class="rounded-none border-2 border-black shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
						<CardHeader>
							<CardTitle>Login (Load Passkey)</CardTitle>
							<CardDescription>Select the identity to sign transactions with.</CardDescription>
						</CardHeader>
						<CardContent>
							<div class="space-y-4">
								<div>
									<Label>Target Wallet Address</Label>
									<Input
										bind:value={userWalletAddress}
										placeholder="0x..."
										class="rounded-none border-black bg-gray-50 font-mono"
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
													<div class="font-mono text-[10px] text-gray-500">
														ID: {cred.id}
													</div>
												</div>
												{#if currentCredentialId === cred.id}<Badge
														class="rounded-none bg-green-600">ACTIVE</Badge
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
												<Label class="text-[10px] font-bold text-gray-500 uppercase"
													>Selected Key Details</Label
												>
												<div class="flex flex-col gap-1 font-mono text-[10px] text-gray-600">
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
							</div>
						</CardContent>
					</Card>

					<Card
						class="rounded-none border-2 border-black shadow-[4px_4px_0px_0px_rgba(0,0,0,1)] {!currentCredentialId ||
						!userWalletAddress
							? 'pointer-events-none opacity-50'
							: ''}"
					>
						<CardHeader>
							<CardTitle class="flex items-center gap-2">
								<span>Execute Transaction</span>
							</CardTitle>
						</CardHeader>
						<CardContent class="space-y-4 p-6">
							<div class="border border-black/20 bg-gray-100 p-3">
								<Label class="text-xs font-bold text-gray-500 uppercase"
									>Relayer (Gas Payer) Private Key</Label
								>
								<Input
									type="password"
									bind:value={relayerPrivateKey}
									placeholder="0x... (Optional, bypasses browser)"
									class="mt-1 h-8 rounded-none border-black font-mono text-xs"
								/>
							</div>

							<div class="flex justify-end">
								<Button
									variant="outline"
									size="sm"
									onclick={debugContractState}
									class="h-6 border-red-500 text-[10px] text-red-600 hover:bg-red-50"
								>
									🐞 Debug Contract State
								</Button>
							</div>

							<Separator />

							<div class="grid grid-cols-2 gap-4">
								<div class="space-y-1">
									<Label>To Address</Label>
									<Input
										bind:value={targetAddress}
										placeholder="0x..."
										class="rounded-none border-black font-mono"
									/>
								</div>
								<div class="space-y-1">
									<Label>Value (ETH)</Label>
									<Input
										bind:value={ethValue}
										placeholder="0.0"
										class="rounded-none border-black font-mono"
									/>
								</div>
							</div>
							<div class="space-y-1">
								<Label>Call Data</Label>
								<Input
									bind:value={callData}
									placeholder="0x"
									class="rounded-none border-black font-mono"
								/>
							</div>
							<Button
								onclick={sendUserOperation}
								disabled={isLoading}
								class="h-12 w-full rounded-none bg-black text-lg font-bold tracking-wider text-white uppercase hover:bg-gray-800"
							>
								{isLoading ? 'Processing...' : 'Sign & Send'}
							</Button>
						</CardContent>
					</Card>
				</TabsContent>
			</Tabs>
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
		<div class="flex-1 space-y-2 overflow-y-auto p-4 font-mono text-xs">
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
