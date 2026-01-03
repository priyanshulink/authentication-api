const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

/**
 * Generate RSA key pair for JWT RS256 signing
 * Public key - shared with client apps for token validation
 * Private key - kept secret on auth server for token signing
 */
function generateRSAKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });

    return { publicKey, privateKey };
}

/**
 * Save keys to files
 */
function saveKeys(publicKey, privateKey, directory = './config/keys') {
    // Create directory if it doesn't exist
    if (!fs.existsSync(directory)) {
        fs.mkdirSync(directory, { recursive: true });
    }

    const publicKeyPath = path.join(directory, 'public.pem');
    const privateKeyPath = path.join(directory, 'private.pem');

    fs.writeFileSync(publicKeyPath, publicKey);
    fs.writeFileSync(privateKeyPath, privateKey);

    console.log('✅ RSA keys generated successfully!');
    console.log(`📄 Public key: ${publicKeyPath}`);
    console.log(`🔐 Private key: ${privateKeyPath}`);
    console.log('\n⚠️  IMPORTANT: Keep private.pem secret! Share only public.pem with client apps.');

    return { publicKeyPath, privateKeyPath };
}

/**
 * Load keys from files
 */
function loadKeys(directory = './config/keys') {
    try {
        const publicKeyPath = path.join(directory, 'public.pem');
        const privateKeyPath = path.join(directory, 'private.pem');

        const publicKey = fs.readFileSync(publicKeyPath, 'utf8');
        const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

        return { publicKey, privateKey };
    } catch (error) {
        console.error('❌ Error loading keys:', error.message);
        console.log('💡 Run: node utils/generateKeys.js to generate new keys');
        throw error;
    }
}

/**
 * Check if keys exist
 */
function keysExist(directory = './config/keys') {
    const publicKeyPath = path.join(directory, 'public.pem');
    const privateKeyPath = path.join(directory, 'private.pem');
    
    return fs.existsSync(publicKeyPath) && fs.existsSync(privateKeyPath);
}

// If run directly, generate and save keys
if (require.main === module) {
    console.log('🔑 Generating RSA key pair for SSO...\n');
    const { publicKey, privateKey } = generateRSAKeyPair();
    saveKeys(publicKey, privateKey);
}

module.exports = {
    generateRSAKeyPair,
    saveKeys,
    loadKeys,
    keysExist
};
