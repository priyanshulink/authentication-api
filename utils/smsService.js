const crypto = require("crypto");

require("dotenv").config();

/**
 * SMS Service for sending OTP
 * Using Twilio (you can replace with any SMS provider)
 * 
 * For testing, OTPs are logged to console
 * In production, integrate with Twilio, AWS SNS, or other SMS gateway
 */

/**
 * Generate 6-digit OTP
 */
const generateOTP = () => {
    return crypto.randomInt(100000, 999999).toString();
};

/**
 * Send OTP via SMS
 * @param {String} mobile - Mobile number with country code
 * @param {String} otp - 6-digit OTP
 * @param {String} name - User name (optional)
 */
const sendOTP = async (mobile, otp, name = 'User') => {
    try {
        // For development/testing - log OTP to console
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('📱 SMS OTP SENT');
        console.log('Mobile:', mobile);
        console.log('OTP:', otp);
        console.log('Message: Your verification code is:', otp);
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

        // TODO: Integrate with actual SMS provider
        // Example with Twilio:
        /*
        const accountSid = process.env.TWILIO_ACCOUNT_SID;
        const authToken = process.env.TWILIO_AUTH_TOKEN;
        const client = require('twilio')(accountSid, authToken);

        const message = await client.messages.create({
            body: `Your verification code is: ${otp}. Valid for 5 minutes. Do not share this code.`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: mobile
        });

        return message.sid;
        */

        // Example with AWS SNS:
        /*
        const AWS = require('aws-sdk');
        const sns = new AWS.SNS({
            region: process.env.AWS_REGION,
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
        });

        const params = {
            Message: `Your verification code is: ${otp}. Valid for 5 minutes. Do not share this code.`,
            PhoneNumber: mobile,
            MessageAttributes: {
                'AWS.SNS.SMS.SenderID': {
                    DataType: 'String',
                    StringValue: 'YourApp'
                },
                'AWS.SNS.SMS.SMSType': {
                    DataType: 'String',
                    StringValue: 'Transactional'
                }
            }
        };

        const result = await sns.publish(params).promise();
        return result.MessageId;
        */

        return true; // Return true for testing

    } catch (error) {
        console.error('SMS sending error:', error);
        throw new Error('Failed to send OTP SMS');
    }
};

/**
 * Send login notification SMS
 * @param {String} mobile - Mobile number
 * @param {String} name - User name
 * @param {String} ip - IP address
 */
const sendLoginNotification = async (mobile, name, ip) => {
    try {
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('📱 LOGIN NOTIFICATION SMS');
        console.log('Mobile:', mobile);
        console.log('Message:', `Hello ${name}, login detected from IP: ${ip}`);
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

        // TODO: Implement actual SMS sending
        return true;

    } catch (error) {
        console.error('SMS notification error:', error);
        // Don't throw error - login notification is not critical
        return false;
    }
};

/**
 * Validate mobile number format
 * @param {String} mobile - Mobile number
 * @param {String} countryCode - Country code (default: +91)
 */
const validateMobileNumber = (mobile, countryCode = '+91') => {
    // Remove spaces and special characters
    const cleanMobile = mobile.replace(/[\s\-\(\)]/g, '');
    
    // Basic validation for Indian numbers (+91)
    if (countryCode === '+91') {
        // Should be 10 digits
        const indianMobileRegex = /^[6-9]\d{9}$/;
        return indianMobileRegex.test(cleanMobile);
    }
    
    // For other countries, basic length check (7-15 digits)
    return /^\d{7,15}$/.test(cleanMobile);
};

/**
 * Format mobile number with country code
 * @param {String} mobile - Mobile number
 * @param {String} countryCode - Country code
 */
const formatMobileNumber = (mobile, countryCode = '+91') => {
    const cleanMobile = mobile.replace(/[\s\-\(\)]/g, '');
    return `${countryCode}${cleanMobile}`;
};

module.exports = {
    generateOTP,
    sendOTP,
    sendLoginNotification,
    validateMobileNumber,
    formatMobileNumber
};
