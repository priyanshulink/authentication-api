const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

// General API rate limiter - 100 requests per 15 minutes
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Strict rate limiter for login - 5 requests per 10 minutes
const loginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 5,
    message: {
        success: false,
        message: 'Too many login attempts from this IP, please try again after 10 minutes.'
    },
    skipSuccessfulRequests: true, // Don't count successful requests
    standardHeaders: true,
    legacyHeaders: false,
});

// OTP verification rate limiter - 10 requests per 15 minutes
const otpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,
    message: {
        success: false,
        message: 'Too many OTP verification attempts, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Password reset rate limiter - 3 requests per hour
const passwordResetLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3,
    message: {
        success: false,
        message: 'Too many password reset requests, please try again after an hour.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Signup rate limiter - 3 signups per hour
const signupLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3,
    message: {
        success: false,
        message: 'Too many accounts created from this IP, please try again after an hour.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Speed limiter - slow down requests after certain threshold
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 50, // Allow 50 requests per 15 minutes at full speed
    delayMs: (hits) => hits * 100, // Add 100ms delay per request after threshold
});

module.exports = {
    apiLimiter,
    loginLimiter,
    otpLimiter,
    passwordResetLimiter,
    signupLimiter,
    speedLimiter
};
