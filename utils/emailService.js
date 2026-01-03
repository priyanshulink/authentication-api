const nodemailer = require("nodemailer");
const crypto = require("crypto");

// Create transporter
const createTransporter = () => {
    return nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        secure: false, // true for 465, false for other ports
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        }
    });
};

// Generate random token
const generateToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Send verification email
const sendVerificationEmail = async (email, token, name) => {
    const transporter = createTransporter();
    const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:4000'}/api/v1/verify-email/${token}`;

    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: email,
        subject: 'Email Verification - Your App',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2>Welcome ${name}!</h2>
                <p>Thank you for registering. Please verify your email address by clicking the button below:</p>
                <a href="${verificationUrl}" 
                   style="display: inline-block; padding: 12px 24px; background-color: #4CAF50; color: white; 
                          text-decoration: none; border-radius: 4px; margin: 20px 0;">
                    Verify Email
                </a>
                <p>Or copy and paste this link in your browser:</p>
                <p style="color: #666; word-break: break-all;">${verificationUrl}</p>
                <p style="color: #999; font-size: 12px; margin-top: 30px;">
                    This link will expire in 24 hours. If you didn't create an account, please ignore this email.
                </p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Verification email sent to ${email}`);
        return true;
    } catch (error) {
        console.error('Error sending verification email:', error);
        throw error;
    }
};

// Send password reset email
const sendPasswordResetEmail = async (email, token, name) => {
    const transporter = createTransporter();
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:4000'}/api/v1/reset-password/${token}`;

    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: email,
        subject: 'Password Reset Request - Your App',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2>Hello ${name},</h2>
                <p>We received a request to reset your password. Click the button below to reset it:</p>
                <a href="${resetUrl}" 
                   style="display: inline-block; padding: 12px 24px; background-color: #f44336; color: white; 
                          text-decoration: none; border-radius: 4px; margin: 20px 0;">
                    Reset Password
                </a>
                <p>Or copy and paste this link in your browser:</p>
                <p style="color: #666; word-break: break-all;">${resetUrl}</p>
                <p style="color: #999; font-size: 12px; margin-top: 30px;">
                    This link will expire in 1 hour. If you didn't request a password reset, please ignore this email.
                </p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Password reset email sent to ${email}`);
        return true;
    } catch (error) {
        console.error('Error sending password reset email:', error);
        throw error;
    }
};

module.exports = {
    generateToken,
    sendVerificationEmail,
    sendPasswordResetEmail
};
