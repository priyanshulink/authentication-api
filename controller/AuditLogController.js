const AuditLog = require("../model/AuditLog");

/**
 * Get user's own audit logs
 */
exports.getMyLogs = async (req, res) => {
    try {
        const userId = req.user.id;
        const limit = parseInt(req.query.limit) || 50;
        
        const logs = await AuditLog.getUserActivity(userId, limit);
        
        res.json({
            success: true,
            count: logs.length,
            logs
        });
    } catch (error) {
        console.error('Error fetching user logs:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch audit logs'
        });
    }
};

/**
 * Get all audit logs (Admin only)
 */
exports.getAllLogs = async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const action = req.query.action || null;
        
        const logs = await AuditLog.getRecentLogs(limit, action);
        
        res.json({
            success: true,
            count: logs.length,
            logs
        });
    } catch (error) {
        console.error('Error fetching all logs:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch audit logs'
        });
    }
};

/**
 * Get security events (Admin only)
 */
exports.getSecurityEvents = async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        
        const logs = await AuditLog.getSecurityEvents(limit);
        
        res.json({
            success: true,
            count: logs.length,
            message: 'Security events (failed logins, account locks, permission denials, token revocations)',
            logs
        });
    } catch (error) {
        console.error('Error fetching security events:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch security events'
        });
    }
};

/**
 * Get audit logs for specific user (Admin only)
 */
exports.getUserLogs = async (req, res) => {
    try {
        const { userId } = req.params;
        const limit = parseInt(req.query.limit) || 50;
        
        const logs = await AuditLog.getUserActivity(userId, limit);
        
        res.json({
            success: true,
            userId,
            count: logs.length,
            logs
        });
    } catch (error) {
        console.error('Error fetching user logs:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user audit logs'
        });
    }
};

/**
 * Clean old audit logs (Admin only)
 */
exports.cleanOldLogs = async (req, res) => {
    try {
        const daysToKeep = parseInt(req.query.days) || 90;
        
        const deletedCount = await AuditLog.cleanOldLogs(daysToKeep);
        
        res.json({
            success: true,
            message: `Cleaned audit logs older than ${daysToKeep} days`,
            deletedCount
        });
    } catch (error) {
        console.error('Error cleaning old logs:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to clean old logs'
        });
    }
};

/**
 * Get audit log statistics (Admin only)
 */
exports.getStatistics = async (req, res) => {
    try {
        const stats = await AuditLog.aggregate([
            {
                $group: {
                    _id: '$action',
                    count: { $sum: 1 }
                }
            },
            { $sort: { count: -1 } }
        ]);
        
        const totalLogs = await AuditLog.countDocuments();
        const last24Hours = await AuditLog.countDocuments({
            timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });
        
        res.json({
            success: true,
            statistics: {
                totalLogs,
                logsLast24Hours: last24Hours,
                byAction: stats
            }
        });
    } catch (error) {
        console.error('Error fetching statistics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch statistics'
        });
    }
};
