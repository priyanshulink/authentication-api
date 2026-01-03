const mongoose = require("mongoose");

const authorizationCodeSchema = new mongoose.Schema({
    code: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    clientId: {
        type: String,
        required: true,
        ref: 'Client'
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    redirectUri: {
        type: String,
        required: true
    },
    scope: {
        type: String,
        default: 'openid profile'
    },
    expiresAt: {
        type: Date,
        required: true
        // TTL index defined below, not here
    },
    isUsed: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// TTL index - automatically delete expired codes
authorizationCodeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Method to check if code is valid
authorizationCodeSchema.methods.isValid = function() {
    return !this.isUsed && this.expiresAt > new Date();
};

// Static method to clean up expired codes
authorizationCodeSchema.statics.cleanExpired = async function() {
    await this.deleteMany({ expiresAt: { $lt: new Date() } });
};

module.exports = mongoose.model("AuthorizationCode", authorizationCodeSchema);
