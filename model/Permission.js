const mongoose = require("mongoose");

const permissionSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    description: {
        type: String,
        required: true
    },
    resource: {
        type: String,
        required: true
    },
    action: {
        type: String,
        required: true,
        enum: ['create', 'read', 'update', 'delete', 'manage']
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Index for faster queries (name index already created by unique: true)
permissionSchema.index({ resource: 1, action: 1 });

module.exports = mongoose.model("Permission", permissionSchema);
