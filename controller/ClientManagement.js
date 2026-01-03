const Client = require("../model/Client");

/**
 * Register a new client application
 * Only authenticated users with proper permissions can register clients
 */
exports.registerClient = async (req, res) => {
    try {
        const { name, redirectUris, allowedScopes, grantTypes } = req.body;

        // Validate required fields
        if (!name || !redirectUris || !Array.isArray(redirectUris) || redirectUris.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Name and at least one redirect URI are required'
            });
        }

        // Generate client credentials
        const { clientId, clientSecret } = Client.generateCredentials();

        // Create client
        const client = await Client.create({
            name,
            clientId,
            clientSecret,
            redirectUris,
            allowedScopes: allowedScopes || ['openid', 'profile'],
            grantTypes: grantTypes || ['authorization_code', 'refresh_token'],
            owner: req.user.id,
            isActive: true
        });

        res.status(201).json({
            success: true,
            message: 'Client registered successfully',
            client: {
                clientId: client.clientId,
                clientSecret: client.clientSecret, // Show only once!
                name: client.name,
                redirectUris: client.redirectUris,
                allowedScopes: client.allowedScopes,
                grantTypes: client.grantTypes
            },
            warning: '⚠️  Save the client_secret now! It will not be shown again.'
        });

    } catch (error) {
        console.error('Client registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to register client'
        });
    }
};

/**
 * Get client details (without secret)
 */
exports.getClient = async (req, res) => {
    try {
        const { clientId } = req.params;

        const client = await Client.findOne({ 
            clientId,
            owner: req.user.id 
        }).select('-clientSecret');

        if (!client) {
            return res.status(404).json({
                success: false,
                message: 'Client not found or access denied'
            });
        }

        res.json({
            success: true,
            client: {
                clientId: client.clientId,
                name: client.name,
                redirectUris: client.redirectUris,
                allowedScopes: client.allowedScopes,
                grantTypes: client.grantTypes,
                isActive: client.isActive,
                createdAt: client.createdAt
            }
        });

    } catch (error) {
        console.error('Get client error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch client details'
        });
    }
};

/**
 * List all clients owned by the user
 */
exports.listClients = async (req, res) => {
    try {
        const clients = await Client.find({ 
            owner: req.user.id 
        }).select('-clientSecret');

        res.json({
            success: true,
            count: clients.length,
            clients: clients.map(c => ({
                clientId: c.clientId,
                name: c.name,
                redirectUris: c.redirectUris,
                isActive: c.isActive,
                createdAt: c.createdAt
            }))
        });

    } catch (error) {
        console.error('List clients error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to list clients'
        });
    }
};

/**
 * Update client (cannot change clientId or clientSecret)
 */
exports.updateClient = async (req, res) => {
    try {
        const { clientId } = req.params;
        const { name, redirectUris, allowedScopes, isActive } = req.body;

        const client = await Client.findOne({ 
            clientId,
            owner: req.user.id 
        });

        if (!client) {
            return res.status(404).json({
                success: false,
                message: 'Client not found or access denied'
            });
        }

        // Update allowed fields
        if (name) client.name = name;
        if (redirectUris) client.redirectUris = redirectUris;
        if (allowedScopes) client.allowedScopes = allowedScopes;
        if (typeof isActive === 'boolean') client.isActive = isActive;

        await client.save();

        res.json({
            success: true,
            message: 'Client updated successfully',
            client: {
                clientId: client.clientId,
                name: client.name,
                redirectUris: client.redirectUris,
                allowedScopes: client.allowedScopes,
                isActive: client.isActive
            }
        });

    } catch (error) {
        console.error('Update client error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update client'
        });
    }
};

/**
 * Delete/deactivate client
 */
exports.deleteClient = async (req, res) => {
    try {
        const { clientId } = req.params;

        const client = await Client.findOneAndUpdate(
            { clientId, owner: req.user.id },
            { isActive: false },
            { new: true }
        );

        if (!client) {
            return res.status(404).json({
                success: false,
                message: 'Client not found or access denied'
            });
        }

        res.json({
            success: true,
            message: 'Client deactivated successfully'
        });

    } catch (error) {
        console.error('Delete client error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete client'
        });
    }
};

/**
 * Regenerate client secret
 */
exports.regenerateSecret = async (req, res) => {
    try {
        const { clientId } = req.params;

        const client = await Client.findOne({ 
            clientId,
            owner: req.user.id 
        });

        if (!client) {
            return res.status(404).json({
                success: false,
                message: 'Client not found or access denied'
            });
        }

        // Generate new secret
        const { clientSecret } = Client.generateCredentials();
        client.clientSecret = clientSecret;
        await client.save();

        res.json({
            success: true,
            message: 'Client secret regenerated successfully',
            clientSecret: clientSecret,
            warning: '⚠️  Save the new client_secret now! It will not be shown again.'
        });

    } catch (error) {
        console.error('Regenerate secret error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to regenerate client secret'
        });
    }
};
