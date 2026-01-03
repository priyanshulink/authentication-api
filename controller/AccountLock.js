const User = require("../model/User");

// Manually unlock account (admin use or support)
exports.unlockAccount = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required"
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (!user.isLocked && user.loginAttempts === 0) {
            return res.status(400).json({
                success: false,
                message: "Account is not locked"
            });
        }

        await user.resetLoginAttempts();

        return res.status(200).json({
            success: true,
            message: "Account unlocked successfully"
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Failed to unlock account",
            details: error.message
        });
    }
};

// Check account lock status
exports.checkLockStatus = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Email is required"
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        if (user.isLocked) {
            const lockTimeRemaining = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.status(200).json({
                success: true,
                isLocked: true,
                lockTimeRemaining: `${lockTimeRemaining} minutes`,
                loginAttempts: user.loginAttempts,
                message: `Account is locked. Try again in ${lockTimeRemaining} minutes.`
            });
        }

        return res.status(200).json({
            success: true,
            isLocked: false,
            loginAttempts: user.loginAttempts,
            attemptsRemaining: 5 - user.loginAttempts,
            message: "Account is not locked"
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: "Failed to check lock status",
            details: error.message
        });
    }
};
