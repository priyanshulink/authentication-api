const bcrypt = require("bcrypt");
const User = require("../model/User");
const Role = require("../model/Role");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const { generateTokenPair } = require("../utils/generateToken");
const { generateToken, sendVerificationEmail } = require("../utils/emailService");
const { logLogin, logLoginFailed, logLogin2FA, logAccountLocked } = require("../utils/auditLogger");

require("dotenv").config();

require("dotenv").config();

//signup route handler
exports.signup = async(req,res)=>{
    try{
        //get data
        const {name,email,password,roleName}= req.body;
        //check if user already exist
        const existingUser = await User.findOne({email});
        if(existingUser){
            return res.status(400).json({
                success:false,
                message:"user already exist",
            });
        }

        //secure password
        let hashedPassword;
        try{
            hashedPassword = await bcrypt.hash(password,10);// .hash is used to secure password (jise hash karna hai vo value, aur no. of round);
        }
        catch(err){
            res.status(500).json({
                success:false,
                message:"error in hashing password",
            });
        }

        // Find role by name (default to 'Student' if not provided)
        const requestedRole = roleName || 'Student';
        const role = await Role.findOne({ name: requestedRole });
        
        if (!role) {
            return res.status(400).json({
                success: false,
                message: `Role '${requestedRole}' not found. Please run the database seeder first.`
            });
        }

        // Generate email verification token
        const verificationToken = generateToken();
        const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

        //create entry for user
        const user = await User.create({
            name,
            email,
            password:hashedPassword,
            role: role._id, // Store ObjectId reference
            roleName: role.name, // Store name for backward compatibility
            emailVerificationToken: verificationToken,
            emailVerificationExpires: verificationExpires
        });

        // Send verification email
        try {
            await sendVerificationEmail(email, verificationToken, name);
        } catch (emailError) {
            console.error("Email sending failed:", emailError);
            // Continue with signup even if email fails
        }

        return res.status(200).json({
            success:true,
            message:"User created successfully. Please check your email to verify your account.",
            role: role.name
        });
    }catch(error){
        console.error(error);
        return res.status(500).json({
            success:false,
            message:"user can't be register, please try again latter",
        })
    }
}
exports.login = async(req,res)=>{
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json(
                { 
                    success: false, 
                    message: 'please fill all the entry' 
                });
        }

        const user = await User.findOne({ email }).populate('role');
        if (!user) {
            await logLoginFailed(req, email, 'User not found');
            return res.status(401).json({
                 success: false, 
                 message: 'Invalid credentials' 
                });
         }

        // Check if account is locked
        if (user.isLocked) {
            await logLoginFailed(req, email, 'Account locked');
            const lockTimeRemaining = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.status(423).json({
                success: false,
                message: `Account is locked due to too many failed login attempts. Please try again in ${lockTimeRemaining} minutes.`
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            // Increment login attempts
            await user.incLoginAttempts();
            
            // Reload user to get updated data
            const updatedUser = await User.findOne({ email });
            
            if (updatedUser.isLocked) {
                await logAccountLocked(req, updatedUser._id, 'Too many failed login attempts');
                return res.status(423).json({
                    success: false,
                    message: 'Too many failed login attempts. Account locked for 10 minutes.'
                });
            }
            
            await logLoginFailed(req, email, `Invalid password - ${5 - updatedUser.loginAttempts} attempts remaining`);
            
            const attemptsLeft = 5 - updatedUser.loginAttempts;
            return res.status(401).json({
                success: false, 
                message: `Invalid credentials. ${attemptsLeft} attempts remaining before account lock.`
            });
        }

        // Reset login attempts on successful password verification
        if (user.loginAttempts > 0) {
            await user.resetLoginAttempts();
        }

        // Check if 2FA is enabled
        if (user.twoFactorEnabled) {
            return res.status(200).json({
                success: true,
                require2FA: true,
                message: 'Please provide your 2FA code',
                email: user.email
            });
        }
        
        // Log successful login
        await logLogin(req, user._id, { twoFactorUsed: false });

        // Generate both access and refresh tokens
        const { accessToken, refreshToken } = await generateTokenPair(user);

        // Set refresh token as httpOnly cookie
        const options = { 
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // HTTPS only in production
            sameSite: 'strict'
        };

        res.cookie('refreshToken', refreshToken, options).status(200).json({ 
            success: true, 
            message: 'Login successful',
            accessToken 
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ success: false, message: 'login fail', details: error.message });
    }
}

// Complete login with 2FA
exports.login2FA = async(req,res)=>{
    try {
        const { email, password, token, recoveryCode } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and password are required' 
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        // Check if account is locked
        if (user.isLocked) {
            const lockTimeRemaining = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.status(423).json({
                success: false,
                message: `Account is locked. Please try again in ${lockTimeRemaining} minutes.`
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            // Increment login attempts
            await user.incLoginAttempts();
            return res.status(401).json({
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        if (!user.twoFactorEnabled) {
            return res.status(400).json({
                success: false,
                message: '2FA is not enabled for this account'
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
                message: 'OTP token or recovery code is required'
            });
        }

        if (!verified) {
            // Don't increment for wrong OTP, only for wrong password
            return res.status(401).json({
                success: false,
                message: 'Invalid OTP or recovery code'
            });
        }

        // Reset login attempts on successful 2FA
        if (user.loginAttempts > 0) {
            await user.resetLoginAttempts();
        }

        // Log successful 2FA login
        await logLogin2FA(req, user._id);

        // Generate tokens after successful 2FA
        const { accessToken, refreshToken } = await generateTokenPair(user);

        const options = { 
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        };

        res.cookie('refreshToken', refreshToken, options).status(200).json({ 
            success: true, 
            message: 'Login successful with 2FA',
            accessToken 
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ 
            success: false, 
            message: '2FA login failed', 
            details: error.message 
        });
    }
}