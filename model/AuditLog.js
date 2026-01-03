const mongoose = require("mongoose");

const auditLogSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        index: true
    },
    action: {
        type: String,
        required: true,
        enum: [
            'LOGIN',
            'LOGIN_FAILED',
            'LOGIN_2FA',
            'LOGOUT',
            'SIGNUP',
            'TOKEN_REFRESH',
            'TOKEN_REVOKED',
            'PASSWORD_RESET_REQUEST',
            'PASSWORD_RESET_COMPLETE',
            'PASSWORD_CHANGE',
            'EMAIL_VERIFICATION',
            '2FA_ENABLED',
            '2FA_DISABLED',
            'ACCOUNT_LOCKED',
            'ACCOUNT_UNLOCKED',
            'CLIENT_REGISTERED',
            'CLIENT_UPDATED',
            'CLIENT_DELETED',
            'OAUTH_AUTHORIZE',
            'OAUTH_TOKEN_ISSUED',
            'PERMISSION_DENIED'
        ],
        index: true
    },
    ip: {
        type: String,
        required: true
    },
    userAgent: {
        type: String,
        default: 'Unknown'
    },
    metadata: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    status: {
        type: String,
        enum: ['SUCCESS', 'FAILURE', 'WARNING'],
        default: 'SUCCESS'
    },
    timestamp: {
        type: Date,
        default: Date.now,
        index: true
    }
});

// Compound index for efficient queries
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ timestamp: -1 }); // For recent logs

// Static method to log an event
auditLogSchema.statics.logEvent = async function(data) {
    try {
        return await this.create(data);
    } catch (error) {
        console.error('Failed to create audit log:', error);
        // Don't throw error - audit logging should not break the application
        return null;
    }
};

// Static method to get user activity
auditLogSchema.statics.getUserActivity = async function(userId, limit = 50) {
    return await this.find({ userId })
        .sort({ timestamp: -1 })
        .limit(limit)
        .lean();
};

// Static method to get recent logs
auditLogSchema.statics.getRecentLogs = async function(limit = 100, action = null) {
    const query = action ? { action } : {};
    return await this.find(query)
        .sort({ timestamp: -1 })
        .limit(limit)
        .populate('userId', 'name email')
        .lean();
};

// Static method to get security events (failed logins, account locks, etc.)
auditLogSchema.statics.getSecurityEvents = async function(limit = 100) {
    return await this.find({
        action: { 
            $in: ['LOGIN_FAILED', 'ACCOUNT_LOCKED', 'PERMISSION_DENIED', 'TOKEN_REVOKED'] 
        }
    })
    .sort({ timestamp: -1 })
    .limit(limit)
    .populate('userId', 'name email')
    .lean();
};

// Static method to clean old logs (optional - for data retention)
auditLogSchema.statics.cleanOldLogs = async function(daysToKeep = 90) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);
    
    const result = await this.deleteMany({ 
        timestamp: { $lt: cutoffDate } 
    });
    
    return result.deletedCount;
};

module.exports = mongoose.model("AuditLog", auditLogSchema);
