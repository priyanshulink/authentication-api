const Permission = require("../model/Permission");
const Role = require("../model/Role");

/**
 * Check if user has specific permission
 * @param {String} permissionName - Name of the permission to check
 */
const hasPermission = (permissionName) => {
    return async (req, res, next) => {
        try {
            if (!req.user || !req.user.id) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required'
                });
            }

            const User = require("../model/User");
            const user = await User.findById(req.user.id).populate({
                path: 'role',
                populate: {
                    path: 'permissions'
                }
            });

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            if (!user.role || !user.role.permissions) {
                return res.status(403).json({
                    success: false,
                    message: 'No role or permissions assigned'
                });
            }

            // Check if user has the required permission
            const hasRequiredPermission = user.role.permissions.some(
                permission => permission.name === permissionName
            );

            if (!hasRequiredPermission) {
                return res.status(403).json({
                    success: false,
                    message: `Access denied. Required permission: ${permissionName}`
                });
            }

            // Attach user's permissions to request for further use
            req.userPermissions = user.role.permissions.map(p => p.name);
            
            next();
        } catch (error) {
            console.error('Permission check error:', error);
            return res.status(500).json({
                success: false,
                message: 'Error checking permissions'
            });
        }
    };
};

/**
 * Check if user has any of the specified permissions
 * @param {Array} permissionNames - Array of permission names
 */
const hasAnyPermission = (...permissionNames) => {
    return async (req, res, next) => {
        try {
            if (!req.user || !req.user.id) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required'
                });
            }

            const User = require("../model/User");
            const user = await User.findById(req.user.id).populate({
                path: 'role',
                populate: {
                    path: 'permissions'
                }
            });

            if (!user || !user.role || !user.role.permissions) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            // Check if user has any of the required permissions
            const hasAnyRequiredPermission = user.role.permissions.some(
                permission => permissionNames.includes(permission.name)
            );

            if (!hasAnyRequiredPermission) {
                return res.status(403).json({
                    success: false,
                    message: `Access denied. Required one of: ${permissionNames.join(', ')}`
                });
            }

            req.userPermissions = user.role.permissions.map(p => p.name);
            next();
        } catch (error) {
            console.error('Permission check error:', error);
            return res.status(500).json({
                success: false,
                message: 'Error checking permissions'
            });
        }
    };
};

/**
 * Check if user has all specified permissions
 * @param {Array} permissionNames - Array of permission names
 */
const hasAllPermissions = (...permissionNames) => {
    return async (req, res, next) => {
        try {
            if (!req.user || !req.user.id) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required'
                });
            }

            const User = require("../model/User");
            const user = await User.findById(req.user.id).populate({
                path: 'role',
                populate: {
                    path: 'permissions'
                }
            });

            if (!user || !user.role || !user.role.permissions) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            const userPermissionNames = user.role.permissions.map(p => p.name);

            // Check if user has all required permissions
            const hasAllRequiredPermissions = permissionNames.every(
                permissionName => userPermissionNames.includes(permissionName)
            );

            if (!hasAllRequiredPermissions) {
                return res.status(403).json({
                    success: false,
                    message: `Access denied. Required all of: ${permissionNames.join(', ')}`
                });
            }

            req.userPermissions = userPermissionNames;
            next();
        } catch (error) {
            console.error('Permission check error:', error);
            return res.status(500).json({
                success: false,
                message: 'Error checking permissions'
            });
        }
    };
};

/**
 * Check if user has role by name (backward compatibility)
 * @param {String} roleName - Name of the role
 */
const hasRole = (roleName) => {
    return async (req, res, next) => {
        try {
            if (!req.user || !req.user.id) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required'
                });
            }

            const User = require("../model/User");
            const user = await User.findById(req.user.id).populate('role');

            if (!user || !user.role) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            if (user.role.name !== roleName) {
                return res.status(403).json({
                    success: false,
                    message: `Access denied. Required role: ${roleName}`
                });
            }

            next();
        } catch (error) {
            console.error('Role check error:', error);
            return res.status(500).json({
                success: false,
                message: 'Error checking role'
            });
        }
    };
};

module.exports = {
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    hasRole
};
