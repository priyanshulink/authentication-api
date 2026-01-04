const mongoose = require("mongoose");

const userSchema = mongoose.Schema({
    name:{
        type:String,
        required:true,
        trim:true,
    },
    email:{
        type:String,
        required:true,
        trim:true,
    },
    password:{
        type:String,
        required:true,
    },
    role:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Role',
        required: true
    },
    // Legacy role field for backward compatibility
    roleName:{
        type:String,
        enum:["Admin","Student","Visitor"]
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    emailVerificationToken: {
        type: String
    },
    emailVerificationExpires: {
        type: Date
    },
    passwordResetToken: {
        type: String
    },
    passwordResetExpires: {
        type: Date
    },
    twoFactorSecret: {
        type: String
    },
    twoFactorEnabled: {
        type: Boolean,
        default: false
    },
    recoveryCodes: [{
        code: String,
        used: {
            type: Boolean,
            default: false
        }
    }],
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: {
        type: Date
    },
    accountLocked: {
        type: Boolean,
        default: false
    },
    // Mobile authentication fields
    mobile: {
        type: String,
        sparse: true,
        trim: true
    },
    countryCode: {
        type: String,
        default: '+91'
    },
    isMobileVerified: {
        type: Boolean,
        default: false
    },
    mobileOTP: {
        type: String
    },
    mobileOTPExpires: {
        type: Date
    },
    mobileOTPAttempts: {
        type: Number,
        default: 0
    },
    lastOTPSentAt: {
        type: Date
    }
});

// Virtual property to check if account is locked
userSchema.virtual('isLocked').get(function() {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
    // If we have a previous lock that has expired, restart at 1
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return this.updateOne({
            $set: { loginAttempts: 1 },
            $unset: { lockUntil: 1, accountLocked: 1 }
        });
    }
    
    // Otherwise increment
    const updates = { $inc: { loginAttempts: 1 } };
    
    // Lock the account if we've reached max attempts (5)
    const maxAttempts = 5;
    const lockTime = 10 * 60 * 1000; // 10 minutes
    
    if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
        updates.$set = { 
            lockUntil: Date.now() + lockTime,
            accountLocked: true
        };
    }
    
    return this.updateOne(updates);
};

// Method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
    return this.updateOne({
        $set: { loginAttempts: 0 },
        $unset: { lockUntil: 1, accountLocked: 1 }
    });
};

module.exports= mongoose.model("user",userSchema);