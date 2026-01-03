// Simple script to generate RSA keys
const { generateRSAKeyPair, saveKeys } = require('./utils/generateKeys');

console.log('🔑 Generating RSA key pair for SSO...\n');
const { publicKey, privateKey } = generateRSAKeyPair();
saveKeys(publicKey, privateKey);
