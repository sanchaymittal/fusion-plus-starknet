const { keccak256 } = require('ethers');

// Test with a simple secret
const secret = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
const hash = keccak256(secret);

console.log('Secret (hex):', secret);
console.log('Secret (BigInt):', BigInt(secret).toString());
console.log('Ethereum keccak256 hash:', hash);
console.log('Hash (BigInt):', BigInt(hash).toString());

// Test the conversion that our TypeScript code does
const secretBigInt = BigInt(secret);
console.log('\nConversion check:');
console.log('Original secret:', secret);
console.log('BigInt(secret):', secretBigInt.toString());
console.log('Should be same:', secretBigInt.toString(16) === secret.slice(2));