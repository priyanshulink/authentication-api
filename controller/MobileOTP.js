const User = require("../model/User");
const bcrypt = require("bcrypt");
const { generateOTP, sendOTP, validateMobileNumber, formatMobileNumber, sendLoginNotification } = require("../utils/smsService");
const { generateTokenPair } = require("../utils/generateToken");
const { logLogin, logLoginFailed } = require("../utils/auditLogger");

require("dotenv").config();

/**
 * Register mobile number with user account
 */
exports.registerMobile = async (req, res) => {
    try {
        const { mobile, countryCode = '+91' } = req.body;
        const userId = req.user.id; // Assuming user is already authenticated

        if (!mobile) {
            return res.status(400).json({
                success: false,
                message: "Mobile number is required"
            });
        }

        // Validate mobile number format
        if (!validateMobileNumber(mobile, countryCode)) {
            return res.status(400).json({
                success: false,
                message: "Invalid mobile number format"
            });
        }

        const formattedMobile = formatMobileNumber(mobile, countryCode);

        // Check if mobile already registered to another user
        const existingMobile = await User.findOne({ 
            mobile: formattedMobile,
            _id: { $ne: userId }
        });

        if (existingMobile) {
            return res.status(400).json({
                success: false,
                message: "Mobile number already registered to another account"
            });
        }

        // Generate OTP
        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

        // Update user with mobile and OTP
        const user = await User.findById(userId);
        user.mobile = formattedMobile;
        user.countryCode = countryCode;
        user.mobileOTP = await bcrypt.hash(otp, 10);
        user.mobileOTPExpires = otpExpires;
        user.mobileOTPAttempts = 0;
        user.lastOTPSentAt = new Date();
        user.isMobileVerified = false;
        await user.save();

        // Send OTP via SMS
        await sendOTP(formattedMobile, otp, user.name);

        return res.status(200).json({
            success: true,
            message: "OTP sent to your mobile number",
            mobile: formattedMobile.replace(/(\d{2})(\d{5})(\d+)/, '$1*****$3') // Mask middle digits
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Failed to register mobile number"
        });
    }
};

/**
 * Verify mobile OTP
 */
exports.verifyMobileOTP = async (req, res) => {
    try {
        const { otp } = req.body;
        const userId = req.user.id;

        if (!otp) {
            return res.status(400).json({
                success: false,
                message: "OTP is required"
            });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (!user.mobile || !user.mobileOTP) {
            return res.status(400).json({
                success: false,
                message: "No OTP pending for verification"
            });
        }

        // Check OTP expiry
        if (user.mobileOTPExpires < Date.now()) {
            return res.status(400).json({
                success: false,
                message: "OTP has expired. Please request a new one."
            });
        }

        // Check OTP attempts (max 5)
        if (user.mobileOTPAttempts >= 5) {
            return res.status(429).json({
                success: false,
                message: "Too many failed attempts. Please request a new OTP."
            });
        }

        // Verify OTP
        const isValidOTP = await bcrypt.compare(otp, user.mobileOTP);
        
        if (!isValidOTP) {
            user.mobileOTPAttempts += 1;
            await user.save();

            return res.status(400).json({
                success: false,
                message: `Invalid OTP. ${5 - user.mobileOTPAttempts} attempts remaining.`
            });
        }

        // OTP verified successfully
        user.isMobileVerified = true;
        user.mobileOTP = undefined;
        user.mobileOTPExpires = undefined;
        user.mobileOTPAttempts = 0;
        await user.save();

        return res.status(200).json({
            success: true,
            message: "Mobile number verified successfully",
            mobile: user.mobile
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Failed to verify OTP"
        });
    }
};

/**
 * Send OTP to registered mobile for login
 */
exports.sendLoginOTP = async (req, res) => {
    try {
        const { mobile, countryCode = '+91' } = req.body;

        if (!mobile) {
            return res.status(400).json({
                success: false,
                message: "Mobile number is required"
            });
        }

        const formattedMobile = formatMobileNumber(mobile, countryCode);

        // Find user by mobile
        const user = await User.findOne({ mobile: formattedMobile });
        if (!user) {
            // Don't reveal if mobile exists or not (security)
            return res.status(200).json({
                success: true,
                message: "If this mobile is registered, you will receive an OTP"
            });
        }

        if (!user.isMobileVerified) {
            return res.status(400).json({
                success: false,
                message: "Mobile number not verified. Please register first."
            });
        }

        // Check if account is locked
        if (user.isLocked) {
            return res.status(423).json({
                success: false,
                message: "Account is temporarily locked due to suspicious activity. Please try again later."
            });
        }

        // Rate limiting - max 1 OTP per minute
        if (user.lastOTPSentAt && (Date.now() - user.lastOTPSentAt.getTime()) < 60000) {
            return res.status(429).json({
                success: false,
                message: "Please wait 1 minute before requesting another OTP"
            });
        }

        // Generate OTP
        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

        // Save OTP
        user.mobileOTP = await bcrypt.hash(otp, 10);
        user.mobileOTPExpires = otpExpires;
        user.mobileOTPAttempts = 0;
        user.lastOTPSentAt = new Date();
        await user.save();

        // Send OTP via SMS
        await sendOTP(formattedMobile, otp, user.name);

        return res.status(200).json({
            success: true,
            message: "OTP sent to your mobile number",
            expiresIn: "5 minutes"
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Failed to send OTP"
        });
    }
};

/**
 * Login with mobile OTP
 */
exports.loginWithMobileOTP = async (req, res) => {
    try {
        const { mobile, otp, countryCode = '+91' } = req.body;

        if (!mobile || !otp) {
            return res.status(400).json({
                success: false,
                message: "Mobile number and OTP are required"
            });
        }

        const formattedMobile = formatMobileNumber(mobile, countryCode);

        // Find user by mobile
        const user = await User.findOne({ mobile: formattedMobile }).populate('role');
        if (!user) {
            await logLoginFailed(null, req.ip, req.headers['user-agent'], 'Mobile not registered');
            return res.status(401).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        // Check if account is locked
        if (user.isLocked) {
            return res.status(423).json({
                success: false,
                message: "Account is temporarily locked. Please try again later."
            });
        }

        // Check if mobile is verified
        if (!user.isMobileVerified) {
            return res.status(400).json({
                success: false,
                message: "Mobile number not verified"
            });
        }

        // Check if OTP exists
        if (!user.mobileOTP || !user.mobileOTPExpires) {
            return res.status(400).json({
                success: false,
                message: "No OTP requested. Please request an OTP first."
            });
        }

        // Check OTP expiry
        if (user.mobileOTPExpires < Date.now()) {
            return res.status(400).json({
                success: false,
                message: "OTP has expired. Please request a new one."
            });
        }

        // Check OTP attempts
        if (user.mobileOTPAttempts >= 5) {
            await user.incLoginAttempts();
            return res.status(429).json({
                success: false,
                message: "Too many failed attempts. Please request a new OTP."
            });
        }

        // Verify OTP
        const isValidOTP = await bcrypt.compare(otp, user.mobileOTP);
        
        if (!isValidOTP) {
            user.mobileOTPAttempts += 1;
            await user.save();
            await user.incLoginAttempts();

            await logLoginFailed(user._id, req.ip, req.headers['user-agent'], 'Invalid OTP');

            return res.status(401).json({
                success: false,
                message: `Invalid OTP. ${5 - user.mobileOTPAttempts} attempts remaining.`
            });
        }

        // OTP verified - login successful
        user.mobileOTP = undefined;
        user.mobileOTPExpires = undefined;
        user.mobileOTPAttempts = 0;
        await user.save();

        // Reset login attempts on successful login
        await user.resetLoginAttempts();

        // Generate tokens
        const { accessToken, refreshToken } = await generateTokenPair(user);

        // Set refresh token in HTTP-only cookie
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        // Log successful login
        await logLogin(user._id, req.ip, req.headers['user-agent']);

        // Send login notification
        await sendLoginNotification(user.mobile, user.name, req.ip);

        return res.status(200).json({
            success: true,
            message: "Login successful",
            accessToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                mobile: user.mobile,
                role: user.role.name
            }
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Login failed"
        });
    }
};

/**
 * Resend OTP
 */
exports.resendOTP = async (req, res) => {
    try {
        const { mobile, countryCode = '+91' } = req.body;

        if (!mobile) {
            return res.status(400).json({
                success: false,
                message: "Mobile number is required"
            });
        }

        const formattedMobile = formatMobileNumber(mobile, countryCode);

        const user = await User.findOne({ mobile: formattedMobile });
        if (!user) {
            return res.status(200).json({
                success: true,
                message: "If this mobile is registered, you will receive an OTP"
            });
        }

        // Rate limiting - max 1 OTP per minute
        if (user.lastOTPSentAt && (Date.now() - user.lastOTPSentAt.getTime()) < 60000) {
            const waitTime = Math.ceil((60000 - (Date.now() - user.lastOTPSentAt.getTime())) / 1000);
            return res.status(429).json({
                success: false,
                message: `Please wait ${waitTime} seconds before requesting another OTP`
            });
        }

        // Generate new OTP
        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 5 * 60 * 1000);

        user.mobileOTP = await bcrypt.hash(otp, 10);
        user.mobileOTPExpires = otpExpires;
        user.mobileOTPAttempts = 0;
        user.lastOTPSentAt = new Date();
        await user.save();

        // Send OTP
        await sendOTP(formattedMobile, otp, user.name);

        return res.status(200).json({
            success: true,
            message: "New OTP sent successfully"
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Failed to resend OTP"
        });
    }
};
