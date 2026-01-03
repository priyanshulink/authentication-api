const mongoose = require("mongoose");
const crypto = require("crypto");

const clientSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    clientId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    clientSecret: {
        type: String,
        required: true
    },
    redirectUris: [{
        type: String,
        required: true,
        validate: {
            validator: function(uri) {
                // Validate URI format
                try {
                    new URL(uri);
                    return true;
                } catch (e) {
                    return false;
                }
            },
            message: 'Invalid redirect URI format'
        }
    }],
    allowedScopes: [{
        type: String,
        enum: ['openid', 'profile', 'email', 'offline_access'],
        default: ['openid', 'profile']
    }],
    grantTypes: [{
        type: String,
        enum: ['authorization_code', 'refresh_token', 'client_credentials'],
        default: ['authorization_code', 'refresh_token']
    }],
    isActive: {
        type: Boolean,
        default: true
    },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Generate client credentials
clientSchema.statics.generateCredentials = function() {
    return {
        clientId: crypto.randomBytes(16).toString('hex'),
        clientSecret: crypto.randomBytes(32).toString('hex')
    };
};

// Update timestamp before saving
clientSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

// Method to verify client secret
clientSchema.methods.verifySecret = function(secret) {
    return this.clientSecret === secret;
};

// Method to validate redirect URI
clientSchema.methods.validateRedirectUri = function(uri) {
    return this.redirectUris.includes(uri);
};

module.exports = mongoose.model("Client", clientSchema);
