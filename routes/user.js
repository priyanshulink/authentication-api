const express = require("express");
const router = express.Router();

//handler
const {login, signup, login2FA} = require("../controller/Auth");
const {refreshToken, logout} = require("../controller/RefreshToken");
const {verifyEmail, forgotPassword, resetPassword} = require("../controller/EmailVerification");
const {setup2FA, verify2FASetup, disable2FA, regenerateRecoveryCodes} = require("../controller/TwoFactor");
const {unlockAccount, checkLockStatus} = require("../controller/AccountLock");
const {authorize, token, getPublicKey, jwks} = require("../controller/OAuth");
const {registerClient, getClient, listClients, updateClient, deleteClient, regenerateSecret} = require("../controller/ClientManagement");
const {getMyLogs, getAllLogs, getSecurityEvents, getUserLogs, cleanOldLogs, getStatistics} = require("../controller/AuditLogController");
const {registerMobile, verifyMobileOTP, sendLoginOTP, loginWithMobileOTP, resendOTP} = require("../controller/MobileOTP");
const {auth, isStudent, isAdmin} = require("../middlewares/auth");
const {loginLimiter, otpLimiter, passwordResetLimiter, signupLimiter, apiLimiter} = require("../middlewares/rateLimiter");
const {hasPermission, hasAnyPermission, hasAllPermissions, hasRole} = require("../middlewares/permissions");

/**
 * @swagger
 * /api/v1/login:
 *   post:
 *     tags: [Authentication]
 *     summary: User login
 *     description: Authenticate user with email and password. Returns access token or requires 2FA if enabled.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 example: SecurePass123!
 *     responses:
 *       200:
 *         description: Login successful or 2FA required
 *         content:
 *           application/json:
 *             schema:
 *               oneOf:
 *                 - type: object
 *                   properties:
 *                     success:
 *                       type: boolean
 *                       example: true
 *                     message:
 *                       type: string
 *                       example: Login successful
 *                     accessToken:
 *                       type: string
 *                     user:
 *                       $ref: '#/components/schemas/User'
 *                 - type: object
 *                   properties:
 *                     success:
 *                       type: boolean
 *                       example: true
 *                     requires2FA:
 *                       type: boolean
 *                       example: true
 *                     tempToken:
 *                       type: string
 *       401:
 *         description: Invalid credentials
 *       423:
 *         description: Account locked
 *       429:
 *         description: Too many login attempts
 */
router.post("/login", loginLimiter, login);

/**
 * @swagger
 * /api/v1/login-2fa:
 *   post:
 *     tags: [Two-Factor Authentication]
 *     summary: Verify 2FA token
 *     description: Complete login by verifying 2FA token or recovery code
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [tempToken]
 *             properties:
 *               tempToken:
 *                 type: string
 *                 description: Temporary token received from /login
 *               token:
 *                 type: string
 *                 description: 6-digit TOTP token from authenticator app
 *                 example: "123456"
 *               recoveryCode:
 *                 type: string
 *                 description: Alternative to token - one-time recovery code
 *     responses:
 *       200:
 *         description: 2FA verification successful
 *       401:
 *         description: Invalid 2FA token or temp token
 */
router.post("/login-2fa", otpLimiter, login2FA);

/**
 * @swagger
 * /api/v1/signup:
 *   post:
 *     tags: [Authentication]
 *     summary: User registration
 *     description: Create new user account with email verification
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, email, password, roleName]
 *             properties:
 *               name:
 *                 type: string
 *                 example: John Doe
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 example: SecurePass123!
 *               roleName:
 *                 type: string
 *                 enum: [Student, Teacher, Admin]
 *                 example: Student
 *     responses:
 *       201:
 *         description: User created successfully
 *       400:
 *         description: Validation error or user already exists
 */
router.post("/signup", signupLimiter, signup);

/**
 * @swagger
 * /api/v1/refresh:
 *   post:
 *     tags: [Authentication]
 *     summary: Refresh access token
 *     description: Get new access token using refresh token from HTTP-only cookie
 *     responses:
 *       200:
 *         description: New access token issued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 accessToken:
 *                   type: string
 *       401:
 *         description: Invalid or expired refresh token
 */
router.post("/refresh", refreshToken);

/**
 * @swagger
 * /api/v1/logout:
 *   post:
 *     tags: [Authentication]
 *     summary: User logout
 *     description: Revoke tokens and logout user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: Refresh token to revoke
 *     responses:
 *       200:
 *         description: Logged out successfully
 */
router.post("/logout", logout);

/**
 * @swagger
 * /api/v1/verify-email/{token}:
 *   get:
 *     tags: [Email Verification]
 *     summary: Verify email address
 *     description: Verify user's email using token sent via email
 *     parameters:
 *       - in: path
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *         description: Email verification token
 *     responses:
 *       200:
 *         description: Email verified successfully
 *       400:
 *         description: Invalid or expired token
 */
router.get("/verify-email/:token", verifyEmail);

/**
 * @swagger
 * /api/v1/forgot-password:
 *   post:
 *     tags: [Email Verification]
 *     summary: Request password reset
 *     description: Send password reset email to user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: If account exists, password reset email will be sent
 */
router.post("/forgot-password", passwordResetLimiter, forgotPassword);

/**
 * @swagger
 * /api/v1/reset-password/{token}:
 *   post:
 *     tags: [Email Verification]
 *     summary: Reset password
 *     description: Set new password using reset token
 *     parameters:
 *       - in: path
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *         description: Password reset token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [password]
 *             properties:
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 example: NewSecurePass123!
 *     responses:
 *       200:
 *         description: Password reset successful
 *       400:
 *         description: Invalid or expired token
 */
router.post("/reset-password/:token", passwordResetLimiter, resetPassword);

/**
 * @swagger
 * /api/v1/account/unlock:
 *   post:
 *     tags: [Account Management]
 *     summary: Unlock user account (Admin only)
 *     description: Unlock a locked user account and reset failed login attempts
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: locked@user.com
 *     responses:
 *       200:
 *         description: Account unlocked successfully
 *       403:
 *         description: Permission denied - requires users:manage
 *       404:
 *         description: User not found
 */
router.post("/account/unlock", auth, hasPermission("users:manage"), unlockAccount);

/**
 * @swagger
 * /api/v1/account/lock-status:
 *   post:
 *     tags: [Account Management]
 *     summary: Check account lock status
 *     description: Check if an account is locked
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Lock status retrieved
 */
router.post("/account/lock-status", checkLockStatus);

/**
 * @swagger
 * /api/v1/2fa/setup:
 *   post:
 *     tags: [Two-Factor Authentication]
 *     summary: Setup 2FA
 *     description: Generate QR code and secret for 2FA setup
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 2FA setup data generated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 qrCode:
 *                   type: string
 *                   description: QR code data URL
 *                 secret:
 *                   type: string
 *                   description: 2FA secret (for manual entry)
 *       400:
 *         description: 2FA already enabled
 */
router.post("/2fa/setup", auth, setup2FA);

/**
 * @swagger
 * /api/v1/2fa/verify-setup:
 *   post:
 *     tags: [Two-Factor Authentication]
 *     summary: Verify and enable 2FA
 *     description: Verify 2FA token and enable 2FA for account
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [token]
 *             properties:
 *               token:
 *                 type: string
 *                 example: "123456"
 *                 description: 6-digit TOTP token
 *     responses:
 *       200:
 *         description: 2FA enabled successfully
 *       401:
 *         description: Invalid token
 */
router.post("/2fa/verify-setup", auth, otpLimiter, verify2FASetup);

/**
 * @swagger
 * /api/v1/2fa/disable:
 *   post:
 *     tags: [Two-Factor Authentication]
 *     summary: Disable 2FA
 *     description: Disable two-factor authentication for account
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 2FA disabled successfully
 */
router.post("/2fa/disable", auth, disable2FA);

/**
 * @swagger
 * /api/v1/2fa/recovery-codes:
 *   post:
 *     tags: [Two-Factor Authentication]
 *     summary: Regenerate recovery codes
 *     description: Generate new set of recovery codes
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: New recovery codes generated
 */
router.post("/2fa/recovery-codes", auth, regenerateRecoveryCodes);

/**
 * @swagger
 * /api/v1/test:
 *   get:
 *     tags: [Testing]
 *     summary: Test protected route
 *     description: Test route to verify authentication is working
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Authentication successful
 *       401:
 *         description: Unauthorized
 */
router.get('/test', auth, (req,res)=>{
    res.json({
        success:true,
        message:'welcome to protected router for test',
        user: req.user,
        permissions: req.userPermissions
    })
})

//protected route for students (using permission-based check)
router.get("/student", auth, hasAnyPermission("posts:create", "comments:create"), (req,res)=>{
    res.json({
        success:true,
        message:'welcome to the protected route for students',
        permissions: req.userPermissions
    })
});

//protected route for admin (using permission-based check)
router.get("/admin", auth, hasPermission("users:manage"), (req,res)=>{
    res.json({
        success:true,
        message:'welcome to protected route for admin',
        permissions: req.userPermissions
    })
})

//alternative: using role-based check (backward compatibility)
router.get("/admin-role", auth, hasRole("Admin"), (req,res)=>{
    res.json({
        success:true,
        message:'admin accessed via role check',
        role: req.user.role.name,
        permissions: req.userPermissions
    })
})

// ============================================
// SSO / OAuth2 Routes
// ============================================

/**
 * @swagger
 * /api/v1/oauth/authorize:
 *   get:
 *     tags: [OAuth2/SSO]
 *     summary: OAuth2 authorization endpoint
 *     description: Step 1 - Request authorization code for OAuth2 flow
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: response_type
 *         required: true
 *         schema:
 *           type: string
 *           enum: [code]
 *       - in: query
 *         name: client_id
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: redirect_uri
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: scope
 *         schema:
 *           type: string
 *           example: read write
 *       - in: query
 *         name: state
 *         schema:
 *           type: string
 *     responses:
 *       302:
 *         description: Redirect to client with authorization code
 *       400:
 *         description: Invalid client or redirect URI
 */
router.get("/oauth/authorize", auth, authorize);

/**
 * @swagger
 * /api/v1/oauth/token:
 *   post:
 *     tags: [OAuth2/SSO]
 *     summary: OAuth2 token endpoint
 *     description: Step 2 - Exchange authorization code for access token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [grant_type, code, client_id, client_secret, redirect_uri]
 *             properties:
 *               grant_type:
 *                 type: string
 *                 enum: [authorization_code, refresh_token]
 *               code:
 *                 type: string
 *                 description: Authorization code (for authorization_code grant)
 *               client_id:
 *                 type: string
 *               client_secret:
 *                 type: string
 *               redirect_uri:
 *                 type: string
 *               refresh_token:
 *                 type: string
 *                 description: Refresh token (for refresh_token grant)
 *     responses:
 *       200:
 *         description: Access token issued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 access_token:
 *                   type: string
 *                 token_type:
 *                   type: string
 *                   example: Bearer
 *                 expires_in:
 *                   type: integer
 *                   example: 3600
 *                 refresh_token:
 *                   type: string
 *       400:
 *         description: Invalid grant
 */
router.post("/oauth/token", token);

/**
 * @swagger
 * /api/v1/oauth/public-key:
 *   get:
 *     tags: [OAuth2/SSO]
 *     summary: Get public key for token validation
 *     description: Retrieve RSA public key for validating RS256 JWT signatures
 *     responses:
 *       200:
 *         description: Public key in PEM format
 */
router.get("/oauth/public-key", getPublicKey);

/**
 * @swagger
 * /api/v1/.well-known/jwks.json:
 *   get:
 *     tags: [OAuth2/SSO]
 *     summary: JWKS endpoint
 *     description: JSON Web Key Set for token validation (standard OAuth2)
 *     responses:
 *       200:
 *         description: JWKS with public keys
 */
router.get("/.well-known/jwks.json", jwks);

/**
 * @swagger
 * /api/v1/oauth/clients:
 *   post:
 *     tags: [Client Management]
 *     summary: Register OAuth client (Admin only)
 *     description: Create a new OAuth2 client application
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, redirectUris]
 *             properties:
 *               name:
 *                 type: string
 *                 example: My Application
 *               redirectUris:
 *                 type: array
 *                 items:
 *                   type: string
 *                 example: ["http://localhost:3000/callback"]
 *               allowedScopes:
 *                 type: array
 *                 items:
 *                   type: string
 *                 example: ["read", "write"]
 *     responses:
 *       201:
 *         description: Client registered successfully
 *       403:
 *         description: Permission denied - Admin only
 *   get:
 *     tags: [Client Management]
 *     summary: List OAuth clients
 *     description: Get list of user's OAuth2 clients
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of clients
 */
router.post("/oauth/clients", auth, hasPermission("users:manage"), registerClient);
router.get("/oauth/clients", auth, listClients);

/**
 * @swagger
 * /api/v1/oauth/clients/{clientId}:
 *   get:
 *     tags: [Client Management]
 *     summary: Get client details
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: clientId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Client details
 *   put:
 *     tags: [Client Management]
 *     summary: Update OAuth client
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: clientId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               redirectUris:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       200:
 *         description: Client updated
 *   delete:
 *     tags: [Client Management]
 *     summary: Delete/deactivate OAuth client
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: clientId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Client deactivated
 */
router.get("/oauth/clients/:clientId", auth, getClient);
router.put("/oauth/clients/:clientId", auth, updateClient);
router.delete("/oauth/clients/:clientId", auth, deleteClient);

/**
 * @swagger
 * /api/v1/oauth/clients/{clientId}/regenerate-secret:
 *   post:
 *     tags: [Client Management]
 *     summary: Regenerate client secret
 *     description: Generate new client secret (invalidates old one)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: clientId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: New secret generated
 */
router.post("/oauth/clients/:clientId/regenerate-secret", auth, regenerateSecret);

// ============================================
// Audit Log Routes
// ============================================

/**
 * @swagger
 * /api/v1/audit/my-logs:
 *   get:
 *     tags: [Audit Logs]
 *     summary: Get my audit logs
 *     description: Retrieve authenticated user's own activity logs
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *     responses:
 *       200:
 *         description: User's audit logs
 */
router.get("/audit/my-logs", auth, getMyLogs);

/**
 * @swagger
 * /api/v1/audit/logs:
 *   get:
 *     tags: [Audit Logs]
 *     summary: Get all audit logs (Admin only)
 *     description: Retrieve all system audit logs with optional filtering
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: action
 *         schema:
 *           type: string
 *           enum: [LOGIN, LOGOUT, TOKEN_REFRESH, PASSWORD_RESET_REQUEST, etc]
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *     responses:
 *       200:
 *         description: All audit logs
 *       403:
 *         description: Permission denied - Admin only
 */
router.get("/audit/logs", auth, hasPermission("users:manage"), getAllLogs);

/**
 * @swagger
 * /api/v1/audit/security-events:
 *   get:
 *     tags: [Audit Logs]
 *     summary: Get security events (Admin only)
 *     description: Retrieve failed logins, lockouts, and permission denials
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *     responses:
 *       200:
 *         description: Security events
 *       403:
 *         description: Admin only
 */
router.get("/audit/security-events", auth, hasPermission("users:manage"), getSecurityEvents);

/**
 * @swagger
 * /api/v1/audit/users/{userId}:
 *   get:
 *     tags: [Audit Logs]
 *     summary: Get user's audit logs (Admin only)
 *     description: Retrieve specific user's activity logs
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *     responses:
 *       200:
 *         description: User's audit logs
 *       403:
 *         description: Admin only
 */
router.get("/audit/users/:userId", auth, hasPermission("users:manage"), getUserLogs);

/**
 * @swagger
 * /api/v1/audit/statistics:
 *   get:
 *     tags: [Audit Logs]
 *     summary: Get audit statistics (Admin only)
 *     description: Retrieve aggregated statistics by action type
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Audit statistics
 *       403:
 *         description: Admin only
 */
router.get("/audit/statistics", auth, hasPermission("users:manage"), getStatistics);

/**
 * @swagger
 * /api/v1/audit/clean:
 *   delete:
 *     tags: [Audit Logs]
 *     summary: Clean old audit logs (Admin only)
 *     description: Remove audit logs older than specified days
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: days
 *         required: true
 *         schema:
 *           type: integer
 *           example: 90
 *         description: Remove logs older than this many days
 *     responses:
 *       200:
 *         description: Old logs cleaned
 *       403:
 *         description: Admin only
 */
router.delete("/audit/clean", auth, hasPermission("users:manage"), cleanOldLogs);

// ===========================
// Mobile OTP Authentication Routes
// ===========================

/**
 * @swagger
 * /api/v1/mobile/register:
 *   post:
 *     tags: [Mobile Authentication]
 *     summary: Register mobile number
 *     description: Add mobile number to user account and send verification OTP
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [mobile]
 *             properties:
 *               mobile:
 *                 type: string
 *                 example: "9876543210"
 *               countryCode:
 *                 type: string
 *                 default: "+91"
 *                 example: "+91"
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *       400:
 *         description: Invalid mobile number or already registered
 *       401:
 *         description: Unauthorized
 */
router.post("/mobile/register", auth, otpLimiter, registerMobile);

/**
 * @swagger
 * /api/v1/mobile/verify:
 *   post:
 *     tags: [Mobile Authentication]
 *     summary: Verify mobile OTP
 *     description: Verify the OTP sent to mobile number
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [otp]
 *             properties:
 *               otp:
 *                 type: string
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: Mobile verified successfully
 *       400:
 *         description: Invalid or expired OTP
 *       401:
 *         description: Unauthorized
 */
router.post("/mobile/verify", auth, otpLimiter, verifyMobileOTP);

/**
 * @swagger
 * /api/v1/mobile/send-login-otp:
 *   post:
 *     tags: [Mobile Authentication]
 *     summary: Send login OTP to mobile
 *     description: Send OTP to registered mobile number for login
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [mobile]
 *             properties:
 *               mobile:
 *                 type: string
 *                 example: "9876543210"
 *               countryCode:
 *                 type: string
 *                 default: "+91"
 *                 example: "+91"
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *       400:
 *         description: Invalid mobile number
 *       423:
 *         description: Account locked
 *       429:
 *         description: Rate limit exceeded
 */
router.post("/mobile/send-login-otp", otpLimiter, sendLoginOTP);

/**
 * @swagger
 * /api/v1/mobile/login:
 *   post:
 *     tags: [Mobile Authentication]
 *     summary: Login with mobile OTP
 *     description: Authenticate user with mobile number and OTP
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [mobile, otp]
 *             properties:
 *               mobile:
 *                 type: string
 *                 example: "9876543210"
 *               otp:
 *                 type: string
 *                 example: "123456"
 *               countryCode:
 *                 type: string
 *                 default: "+91"
 *                 example: "+91"
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 accessToken:
 *                   type: string
 *                 user:
 *                   type: object
 *       401:
 *         description: Invalid credentials
 *       423:
 *         description: Account locked
 */
router.post("/mobile/login", loginLimiter, loginWithMobileOTP);

/**
 * @swagger
 * /api/v1/mobile/resend-otp:
 *   post:
 *     tags: [Mobile Authentication]
 *     summary: Resend OTP
 *     description: Resend OTP to mobile number (rate limited to 1 per minute)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [mobile]
 *             properties:
 *               mobile:
 *                 type: string
 *                 example: "9876543210"
 *               countryCode:
 *                 type: string
 *                 default: "+91"
 *                 example: "+91"
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *       429:
 *         description: Rate limit - wait before requesting again
 */
router.post("/mobile/resend-otp", otpLimiter, resendOTP);

module.exports = router;