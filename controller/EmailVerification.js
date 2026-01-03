const User = require("../model/User");
const bcrypt = require("bcrypt");
const { generateToken, sendPasswordResetEmail } = require("../utils/emailService");
const { logEmailVerification, logPasswordResetRequest, logPasswordResetComplete } = require("../utils/auditLogger");

require("dotenv").config();

// Email Verification
exports.verifyEmail = async (req, res) => {
    try {
        const { token } = req.params;

        if (!token) {
            return res.status(400).json({
                success: false,
                message: "Verification token is required"
            });
        }

        // Find user with this token
        const user = await User.findOne({
            emailVerificationToken: token,
            emailVerificationExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid or expired verification token"
            });
        }

        // Verify the email
        user.isEmailVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;
        await user.save();

        // Log email verification
        await logEmailVerification(req, user._id);

        return res.status(200).json({
            success: true,
            message: "Email verified successfully! You can now login."
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Email verification failed",
            details: error.message
        });
    }
};

// Forgot Password
exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required"
            });
        }

        // Find user
        const user = await User.findOne({ email });

        if (!user) {
            // Don't reveal if user exists or not for security
            return res.status(200).json({
                success: true,
                message: "If an account exists with this email, a password reset link has been sent."
            });
        }

        // Generate reset token
        const resetToken = generateToken();
        const resetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

        user.passwordResetToken = resetToken;
        user.passwordResetExpires = resetExpires;
        await user.save();

        // Send reset email
        try {
            await sendPasswordResetEmail(email, resetToken, user.name);
            
            // Log password reset request
            await logPasswordResetRequest(req, user._id, email);
        } catch (emailError) {
            console.error("Email sending failed:", emailError);
            return res.status(500).json({
                success: false,
                message: "Failed to send password reset email"
            });
        }

        return res.status(200).json({
            success: true,
            message: "Password reset link has been sent to your email."
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Password reset request failed",
            details: error.message
        });
    }
};

// Reset Password
exports.resetPassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        if (!token) {
            return res.status(400).json({
                success: false,
                message: "Reset token is required"
            });
        }

        if (!password) {
            return res.status(400).json({
                success: false,
                message: "New password is required"
            });
        }

        // Find user with valid reset token
        const user = await User.findOne({
            passwordResetToken: token,
            passwordResetExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid or expired reset token"
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update password and clear reset token
        user.password = hashedPassword;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save();

        // Log password reset completion
        await logPasswordResetComplete(req, user._id);

        return res.status(200).json({
            success: true,
            message: "Password reset successful! You can now login with your new password."
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Password reset failed",
            details: error.message
        });
    }
};
