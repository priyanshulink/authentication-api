const jwt = require("jsonwebtoken");
const User = require("../model/User");
const RefreshToken = require("../model/RefreshToken");
const TokenBlacklist = require("../model/TokenBlacklist");
const { generateTokenPair } = require("../utils/generateToken");
const { logTokenRefresh, logLogout, logTokenRevoked } = require("../utils/auditLogger");

require("dotenv").config();

exports.refreshToken = async (req, res) => {
    try {
        // Get refresh token from cookie or body
        const oldRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

        if (!oldRefreshToken) {
            return res.status(401).json({
                success: false,
                message: "Refresh token not provided"
            });
        }

        // Verify the refresh token
        let decoded;
        try {
            decoded = jwt.verify(oldRefreshToken, process.env.REFRESH_TOKEN_SECRET);
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: "Invalid or expired refresh token"
            });
        }

        // Check if refresh token exists in database and is not revoked
        const storedToken = await RefreshToken.findOne({
            token: oldRefreshToken,
            userId: decoded.userId
        });

        if (!storedToken) {
            return res.status(401).json({
                success: false,
                message: "Refresh token not found"
            });
        }

        if (storedToken.isRevoked) {
            return res.status(401).json({
                success: false,
                message: "Refresh token has been revoked"
            });
        }

        if (new Date() > storedToken.expiresAt) {
            return res.status(401).json({
                success: false,
                message: "Refresh token expired"
            });
        }

        // Get user details
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        // Revoke old refresh token (Token Rotation)
        storedToken.isRevoked = true;
        await storedToken.save();

        // Generate new token pair
        const { accessToken, refreshToken: newRefreshToken } = await generateTokenPair(user);

        // Log token refresh
        await logTokenRefresh(req, user._id);

        // Set new refresh token as httpOnly cookie
        const options = {
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        };

        res.cookie('refreshToken', newRefreshToken, options).status(200).json({
            success: true,
            message: "Token refreshed successfully",
            accessToken
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Failed to refresh token",
            details: error.message
        });
    }
};

// Logout endpoint to revoke tokens and blacklist access token
exports.logout = async (req, res) => {
    try {
        // Get tokens from request
        const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
        const authHeader = req.headers.authorization;
        
        // Extract access token
        let accessToken = null;
        if (authHeader && authHeader.startsWith("Bearer ")) {
            accessToken = authHeader.split(" ")[1];
        }

        // Revoke refresh token if provided
        if (refreshToken) {
            await RefreshToken.updateOne(
                { token: refreshToken },
                { isRevoked: true }
            );
        }

        // Blacklist access token if provided
        if (accessToken) {
            try {
                const decoded = jwt.decode(accessToken);
                
                if (decoded && decoded.exp) {
                    await TokenBlacklist.create({
                        token: accessToken,
                        userId: decoded.userId,
                        expiresAt: new Date(decoded.exp * 1000),
                        reason: "logout"
                    });
                }
            } catch (error) {
                console.error("Error blacklisting access token:", error);
                // Continue with logout even if blacklist fails
            }
        }

        // Clear the refresh token cookie
        res.clearCookie('refreshToken');

        // Log logout event
        if (req.user && req.user.id) {
            await logLogout(req, req.user.id);
            await logTokenRevoked(req, req.user.id, 'User logout');
        }

        return res.status(200).json({
            success: true,
            message: "Logged out successfully"
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Logout failed",
            details: error.message
        });
    }
};
