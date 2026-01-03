const Client = require("../model/Client");
const AuthorizationCode = require("../model/AuthorizationCode");
const User = require("../model/User");
const crypto = require("crypto");
const { generateTokenPair } = require("../utils/generateToken");
const { logOAuthAuthorize, logOAuthTokenIssued } = require("../utils/auditLogger");

/**
 * OAuth2 Authorization Endpoint
 * Step 1: User authorizes client app to access their account
 * 
 * Query Parameters:
 * - response_type: "code" (for authorization code flow)
 * - client_id: Client application ID
 * - redirect_uri: Where to redirect after authorization
 * - scope: Requested permissions (optional)
 * - state: CSRF protection token (recommended)
 */
exports.authorize = async (req, res) => {
    try {
        const { response_type, client_id, redirect_uri, scope, state } = req.query;

        // Validate required parameters
        if (!response_type || !client_id || !redirect_uri) {
            return res.status(400).json({
                success: false,
                error: 'invalid_request',
                message: 'Missing required parameters: response_type, client_id, redirect_uri'
            });
        }

        // Only support authorization_code flow
        if (response_type !== 'code') {
            return res.status(400).json({
                success: false,
                error: 'unsupported_response_type',
                message: 'Only authorization_code flow (response_type=code) is supported'
            });
        }

        // Verify client exists and is active
        const client = await Client.findOne({ clientId: client_id, isActive: true });
        if (!client) {
            return res.status(401).json({
                success: false,
                error: 'invalid_client',
                message: 'Invalid or inactive client'
            });
        }

        // Validate redirect URI
        if (!client.validateRedirectUri(redirect_uri)) {
            return res.status(400).json({
                success: false,
                error: 'invalid_redirect_uri',
                message: 'Redirect URI not registered for this client'
            });
        }

        // Check if user is authenticated (should be logged in)
        if (!req.user || !req.user.id) {
            // In real implementation, redirect to login page with return URL
            return res.status(401).json({
                success: false,
                error: 'login_required',
                message: 'User must be logged in to authorize client',
                loginUrl: `/login?return_to=${encodeURIComponent(req.originalUrl)}`
            });
        }

        // Generate authorization code
        const code = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        await AuthorizationCode.create({
            code,
            clientId: client_id,
            userId: req.user.id,
            redirectUri: redirect_uri,
            scope: scope || 'openid profile',
            expiresAt
        });

        // Log OAuth authorization
        await logOAuthAuthorize(req, req.user.id, client_id);

        // Build redirect URL with code
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.append('code', code);
        if (state) {
            redirectUrl.searchParams.append('state', state);
        }

        // In real implementation, show consent screen first
        // For now, auto-approve and redirect
        res.json({
            success: true,
            message: 'Authorization granted',
            redirectUrl: redirectUrl.toString(),
            code: code // Only for testing, don't send in production
        });

    } catch (error) {
        console.error('Authorization error:', error);
        res.status(500).json({
            success: false,
            error: 'server_error',
            message: 'Internal server error'
        });
    }
};

/**
 * OAuth2 Token Endpoint
 * Step 2: Exchange authorization code for access token
 * 
 * Body Parameters:
 * - grant_type: "authorization_code" or "refresh_token"
 * - code: Authorization code (for authorization_code grant)
 * - redirect_uri: Must match the one used in authorize
 * - client_id: Client application ID
 * - client_secret: Client secret for authentication
 * - refresh_token: Refresh token (for refresh_token grant)
 */
exports.token = async (req, res) => {
    try {
        const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;

        // Validate client credentials
        const client = await Client.findOne({ clientId: client_id });
        if (!client || !client.verifySecret(client_secret)) {
            return res.status(401).json({
                success: false,
                error: 'invalid_client',
                message: 'Invalid client credentials'
            });
        }

        // Handle authorization_code grant
        if (grant_type === 'authorization_code') {
            if (!code || !redirect_uri) {
                return res.status(400).json({
                    success: false,
                    error: 'invalid_request',
                    message: 'Missing code or redirect_uri'
                });
            }

            // Find and validate authorization code
            const authCode = await AuthorizationCode.findOne({ 
                code, 
                clientId: client_id,
                redirectUri: redirect_uri
            });

            if (!authCode || !authCode.isValid()) {
                return res.status(400).json({
                    success: false,
                    error: 'invalid_grant',
                    message: 'Invalid, expired, or already used authorization code'
                });
            }

            // Mark code as used
            authCode.isUsed = true;
            await authCode.save();

            // Get user and populate role
            const user = await User.findById(authCode.userId).populate('role');
            if (!user) {
                return res.status(400).json({
                    success: false,
                    error: 'invalid_grant',
                    message: 'User not found'
                });
            }

            // Generate tokens with clientId
            const tokens = await generateTokenPair(user, client_id);

            // Log OAuth token issued
            await logOAuthTokenIssued(req, user._id, client_id);

            return res.json({
                success: true,
                access_token: tokens.accessToken,
                refresh_token: tokens.refreshToken,
                token_type: 'Bearer',
                expires_in: 900, // 15 minutes
                scope: authCode.scope
            });
        }

        // Handle refresh_token grant
        if (grant_type === 'refresh_token') {
            if (!refresh_token) {
                return res.status(400).json({
                    success: false,
                    error: 'invalid_request',
                    message: 'Missing refresh_token'
                });
            }

            // Implement refresh token logic here
            // Similar to existing RefreshToken controller
            return res.status(501).json({
                success: false,
                error: 'unsupported_grant_type',
                message: 'Refresh token grant not yet implemented for SSO'
            });
        }

        // Unsupported grant type
        return res.status(400).json({
            success: false,
            error: 'unsupported_grant_type',
            message: 'Grant type must be authorization_code or refresh_token'
        });

    } catch (error) {
        console.error('Token error:', error);
        res.status(500).json({
            success: false,
            error: 'server_error',
            message: 'Internal server error'
        });
    }
};

/**
 * Get public key for token validation
 * Client apps use this to verify JWT signatures
 */
exports.getPublicKey = (req, res) => {
    const { getPublicKey } = require("../utils/generateToken");
    const publicKey = getPublicKey();

    if (!publicKey) {
        return res.status(503).json({
            success: false,
            message: 'Public key not available. RSA keys not configured.'
        });
    }

    res.type('text/plain').send(publicKey);
};

/**
 * JWKS (JSON Web Key Set) endpoint
 * Standard way for client apps to discover public keys
 */
exports.jwks = async (req, res) => {
    try {
        const { getPublicKey } = require("../utils/generateToken");
        const publicKey = getPublicKey();

        if (!publicKey) {
            return res.status(503).json({
                error: 'Public key not available'
            });
        }

        // Convert PEM to JWK format (simplified version)
        // In production, use a library like node-jose
        res.json({
            keys: [{
                kty: 'RSA',
                use: 'sig',
                alg: 'RS256',
                kid: 'auth-server-key-1',
                n: 'base64_encoded_modulus', // Placeholder
                e: 'AQAB'
            }]
        });
    } catch (error) {
        console.error('JWKS error:', error);
        res.status(500).json({
            error: 'Internal server error'
        });
    }
};
