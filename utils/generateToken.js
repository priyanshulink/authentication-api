const jwt = require("jsonwebtoken");
const RefreshToken = require("../model/RefreshToken");
const { loadKeys } = require("./generateKeys");

// Load RSA keys for RS256 signing
let privateKey, publicKey;
try {
  const keys = loadKeys();
  privateKey = keys.privateKey;
  publicKey = keys.publicKey;
} catch (error) {
  console.warn("⚠️  RSA keys not found. Using HS256 (symmetric) algorithm.");
  console.warn("💡 For SSO, run: node generateKeys.js to create RS256 keys.");
}

const generateAccessToken = (user, clientId = null) => {
  const payload = {
    userId: user._id,
    role: user.role,
    ...(clientId && { clientId }), // Include clientId for SSO tokens
    aud: clientId || 'default', // Audience claim
    iss: 'auth-server' // Issuer claim
  };

  // Use RS256 if keys are available, otherwise fall back to HS256
  if (privateKey) {
    return jwt.sign(payload, privateKey, {
      algorithm: 'RS256',
      expiresIn: process.env.ACCESS_TOKEN_EXPIRE // 15m
    });
  } else {
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
      algorithm: 'HS256',
      expiresIn: process.env.ACCESS_TOKEN_EXPIRE // 15m
    });
  }
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    {
      userId: user._id
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRE // 7d
    }
  );
};

const storeRefreshToken = async (userId, refreshToken) => {
  const decoded = jwt.decode(refreshToken);
  const expiresAt = new Date(decoded.exp * 1000);

  await RefreshToken.create({
    userId,
    token: refreshToken,
    expiresAt
  });
};

const generateTokenPair = async (user, clientId = null) => {
  const accessToken = generateAccessToken(user, clientId);
  const refreshToken = generateRefreshToken(user);
  
  await storeRefreshToken(user._id, refreshToken);
  
  return { accessToken, refreshToken };
};

// Export public key for client apps to validate tokens
const getPublicKey = () => {
  return publicKey;
};

module.exports = { 
  generateAccessToken, 
  generateRefreshToken, 
  storeRefreshToken,
  generateTokenPair,
  getPublicKey
};
