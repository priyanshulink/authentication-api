const TokenBlacklist = require("../model/TokenBlacklist");

/**
 * Middleware to check if access token is blacklisted
 * Should be used after token verification
 */
exports.checkBlacklist = async (req, res, next) => {
    try {
        // Get token from Authorization header
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return next(); // No token to check, let auth middleware handle it
        }

        const token = authHeader.split(" ")[1];

        // Check if token is blacklisted
        const blacklisted = await TokenBlacklist.findOne({ token });

        if (blacklisted) {
            return res.status(401).json({
                success: false,
                message: "Token has been revoked. Please login again."
            });
        }

        // Token is not blacklisted, proceed
        next();
    } catch (error) {
        console.error("Blacklist check error:", error);
        return res.status(500).json({
            success: false,
            message: "Error checking token validity"
        });
    }
};

/**
 * Utility function to check if a token is blacklisted
 * Can be used in other parts of the application
 */
exports.isTokenBlacklisted = async (token) => {
    try {
        const blacklisted = await TokenBlacklist.findOne({ token });
        return !!blacklisted;
    } catch (error) {
        console.error("Error checking blacklist:", error);
        return false;
    }
};
