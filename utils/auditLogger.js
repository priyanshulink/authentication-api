const AuditLog = require("../model/AuditLog");

/**
 * Extract client IP from request
 * Handles proxies, load balancers, and direct connections
 */
const getClientIp = (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0] ||
           req.headers['x-real-ip'] ||
           req.connection.remoteAddress ||
           req.socket.remoteAddress ||
           'Unknown';
};

/**
 * Extract user agent from request
 */
const getUserAgent = (req) => {
    return req.headers['user-agent'] || 'Unknown';
};

/**
 * Log an audit event
 * @param {Object} params - Audit log parameters
 * @param {String} params.action - Action type (LOGIN, LOGOUT, etc.)
 * @param {String} params.userId - User ID (optional)
 * @param {Object} params.req - Express request object
 * @param {String} params.status - SUCCESS, FAILURE, WARNING (optional)
 * @param {Object} params.metadata - Additional data (optional)
 */
const logAuditEvent = async ({ action, userId = null, req, status = 'SUCCESS', metadata = {} }) => {
    try {
        const auditData = {
            action,
            userId,
            ip: getClientIp(req),
            userAgent: getUserAgent(req),
            status,
            metadata
        };

        await AuditLog.logEvent(auditData);
        console.log(`[AUDIT] ${action} - User: ${userId || 'N/A'} - IP: ${auditData.ip} - Status: ${status}`);
    } catch (error) {
        console.error('Audit logging error:', error);
        // Don't throw - audit logging should not break the application
    }
};

/**
 * Log successful login
 */
const logLogin = async (req, userId, metadata = {}) => {
    await logAuditEvent({
        action: 'LOGIN',
        userId,
        req,
        status: 'SUCCESS',
        metadata: {
            loginMethod: metadata.twoFactorUsed ? '2FA' : 'PASSWORD',
            ...metadata
        }
    });
};

/**
 * Log failed login attempt
 */
const logLoginFailed = async (req, email, reason) => {
    await logAuditEvent({
        action: 'LOGIN_FAILED',
        userId: null,
        req,
        status: 'FAILURE',
        metadata: { email, reason }
    });
};

/**
 * Log 2FA login
 */
const logLogin2FA = async (req, userId) => {
    await logAuditEvent({
        action: 'LOGIN_2FA',
        userId,
        req,
        status: 'SUCCESS'
    });
};

/**
 * Log logout
 */
const logLogout = async (req, userId, metadata = {}) => {
    await logAuditEvent({
        action: 'LOGOUT',
        userId,
        req,
        status: 'SUCCESS',
        metadata
    });
};

/**
 * Log token refresh
 */
const logTokenRefresh = async (req, userId) => {
    await logAuditEvent({
        action: 'TOKEN_REFRESH',
        userId,
        req,
        status: 'SUCCESS'
    });
};

/**
 * Log token revocation
 */
const logTokenRevoked = async (req, userId, reason = 'Manual logout') => {
    await logAuditEvent({
        action: 'TOKEN_REVOKED',
        userId,
        req,
        status: 'SUCCESS',
        metadata: { reason }
    });
};

/**
 * Log password reset request
 */
const logPasswordResetRequest = async (req, userId, email) => {
    await logAuditEvent({
        action: 'PASSWORD_RESET_REQUEST',
        userId,
        req,
        status: 'SUCCESS',
        metadata: { email }
    });
};

/**
 * Log password reset completion
 */
const logPasswordResetComplete = async (req, userId) => {
    await logAuditEvent({
        action: 'PASSWORD_RESET_COMPLETE',
        userId,
        req,
        status: 'SUCCESS'
    });
};

/**
 * Log password change
 */
const logPasswordChange = async (req, userId) => {
    await logAuditEvent({
        action: 'PASSWORD_CHANGE',
        userId,
        req,
        status: 'SUCCESS'
    });
};

/**
 * Log email verification
 */
const logEmailVerification = async (req, userId) => {
    await logAuditEvent({
        action: 'EMAIL_VERIFICATION',
        userId,
        req,
        status: 'SUCCESS'
    });
};

/**
 * Log 2FA enabled
 */
const log2FAEnabled = async (req, userId) => {
    await logAuditEvent({
        action: '2FA_ENABLED',
        userId,
        req,
        status: 'SUCCESS'
    });
};

/**
 * Log 2FA disabled
 */
const log2FADisabled = async (req, userId) => {
    await logAuditEvent({
        action: '2FA_DISABLED',
        userId,
        req,
        status: 'WARNING'
    });
};

/**
 * Log account locked
 */
const logAccountLocked = async (req, userId, reason = 'Too many failed login attempts') => {
    await logAuditEvent({
        action: 'ACCOUNT_LOCKED',
        userId,
        req,
        status: 'WARNING',
        metadata: { reason }
    });
};

/**
 * Log account unlocked
 */
const logAccountUnlocked = async (req, userId, unlockedBy) => {
    await logAuditEvent({
        action: 'ACCOUNT_UNLOCKED',
        userId,
        req,
        status: 'SUCCESS',
        metadata: { unlockedBy }
    });
};

/**
 * Log OAuth authorization
 */
const logOAuthAuthorize = async (req, userId, clientId) => {
    await logAuditEvent({
        action: 'OAUTH_AUTHORIZE',
        userId,
        req,
        status: 'SUCCESS',
        metadata: { clientId }
    });
};

/**
 * Log OAuth token issued
 */
const logOAuthTokenIssued = async (req, userId, clientId) => {
    await logAuditEvent({
        action: 'OAUTH_TOKEN_ISSUED',
        userId,
        req,
        status: 'SUCCESS',
        metadata: { clientId }
    });
};

/**
 * Log permission denied
 */
const logPermissionDenied = async (req, userId, permission) => {
    await logAuditEvent({
        action: 'PERMISSION_DENIED',
        userId,
        req,
        status: 'FAILURE',
        metadata: { permission }
    });
};

/**
 * Log client registration
 */
const logClientRegistered = async (req, userId, clientId, clientName) => {
    await logAuditEvent({
        action: 'CLIENT_REGISTERED',
        userId,
        req,
        status: 'SUCCESS',
        metadata: { clientId, clientName }
    });
};

module.exports = {
    logAuditEvent,
    logLogin,
    logLoginFailed,
    logLogin2FA,
    logLogout,
    logTokenRefresh,
    logTokenRevoked,
    logPasswordResetRequest,
    logPasswordResetComplete,
    logPasswordChange,
    logEmailVerification,
    log2FAEnabled,
    log2FADisabled,
    logAccountLocked,
    logAccountUnlocked,
    logOAuthAuthorize,
    logOAuthTokenIssued,
    logPermissionDenied,
    logClientRegistered,
    getClientIp,
    getUserAgent
};
