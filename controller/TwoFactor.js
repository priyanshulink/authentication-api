const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const crypto = require("crypto");
const User = require("../model/User");
const { log2FAEnabled, log2FADisabled } = require("../utils/auditLogger");

require("dotenv").config();

// Setup 2FA - Generate secret and QR code
exports.setup2FA = async (req, res) => {
    try {
        const userId = req.user.id;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (user.twoFactorEnabled) {
            return res.status(400).json({
                success: false,
                message: "2FA is already enabled"
            });
        }

        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `YourApp (${user.email})`,
            length: 32
        });

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        // Save secret (temporarily) - not enabled yet
        user.twoFactorSecret = secret.base32;
        await user.save();

        return res.status(200).json({
            success: true,
            message: "Scan this QR code with Google Authenticator",
            secret: secret.base32,
            qrCode: qrCodeUrl
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Failed to setup 2FA",
            details: error.message
        });
    }
};

// Verify 2FA setup and enable it
exports.verify2FASetup = async (req, res) => {
    try {
        const userId = req.user.id;
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({
                success: false,
                message: "OTP token is required"
            });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (!user.twoFactorSecret) {
            return res.status(400).json({
                success: false,
                message: "Please setup 2FA first"
            });
        }

        // Verify the token
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: token,
            window: 2
        });

        if (!verified) {
            return res.status(400).json({
                success: false,
                message: "Invalid OTP token"
            });
        }

        // Generate recovery codes
        const recoveryCodes = [];
        for (let i = 0; i < 10; i++) {
            const code = crypto.randomBytes(4).toString('hex').toUpperCase();
            recoveryCodes.push({
                code: code,
                used: false
            });
        }

        // Enable 2FA
        user.twoFactorEnabled = true;
        user.recoveryCodes = recoveryCodes;
        await user.save();

        // Log 2FA enabled
        await log2FAEnabled(req, user._id);

        return res.status(200).json({
            success: true,
            message: "2FA enabled successfully",
            recoveryCodes: recoveryCodes.map(rc => rc.code)
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Failed to verify 2FA",
            details: error.message
        });
    }
};

// Verify OTP during login
exports.verify2FALogin = async (req, res) => {
    try {
        const { email, token, recoveryCode } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required"
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        if (!user.twoFactorEnabled) {
            return res.status(400).json({
                success: false,
                message: "2FA is not enabled for this account"
            });
        }

        let verified = false;

        // Check if using recovery code
        if (recoveryCode) {
            const recoveryCodeEntry = user.recoveryCodes.find(
                rc => rc.code === recoveryCode.toUpperCase() && !rc.used
            );

            if (recoveryCodeEntry) {
                recoveryCodeEntry.used = true;
                await user.save();
                verified = true;
            }
        } 
        // Check OTP token
        else if (token) {
            verified = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: 'base32',
                token: token,
                window: 2
            });
        } else {
            return res.status(400).json({
                success: false,
                message: "OTP token or recovery code is required"
            });
        }

        if (!verified) {
            return res.status(401).json({
                success: false,
                message: "Invalid OTP or recovery code"
            });
        }

        return res.status(200).json({
            success: true,
            message: "2FA verification successful"
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "2FA verification failed",
            details: error.message
        });
    }
};

// Disable 2FA
exports.disable2FA = async (req, res) => {
    try {
        const userId = req.user.id;
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({
                success: false,
                message: "Password is required to disable 2FA"
            });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        // Verify password
        const bcrypt = require("bcrypt");
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: "Invalid password"
            });
        }

        // Disable 2FA
        user.twoFactorEnabled = false;
        user.twoFactorSecret = undefined;
        user.recoveryCodes = [];
        await user.save();

        // Log 2FA disabled
        await log2FADisabled(req, user._id);

        return res.status(200).json({
            success: true,
            message: "2FA disabled successfully"
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Failed to disable 2FA",
            details: error.message
        });
    }
};

// Regenerate recovery codes
exports.regenerateRecoveryCodes = async (req, res) => {
    try {
        const userId = req.user.id;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (!user.twoFactorEnabled) {
            return res.status(400).json({
                success: false,
                message: "2FA is not enabled"
            });
        }

        // Generate new recovery codes
        const recoveryCodes = [];
        for (let i = 0; i < 10; i++) {
            const code = crypto.randomBytes(4).toString('hex').toUpperCase();
            recoveryCodes.push({
                code: code,
                used: false
            });
        }

        user.recoveryCodes = recoveryCodes;
        await user.save();

        return res.status(200).json({
            success: true,
            message: "Recovery codes regenerated successfully",
            recoveryCodes: recoveryCodes.map(rc => rc.code)
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Failed to regenerate recovery codes",
            details: error.message
        });
    }
};
