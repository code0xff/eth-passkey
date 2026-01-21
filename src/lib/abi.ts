export const CONTRACT_ABI = [
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
			{ name: 'targetContract', type: 'address' },
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
