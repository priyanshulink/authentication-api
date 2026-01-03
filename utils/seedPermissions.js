const Permission = require("../model/Permission");
const Role = require("../model/Role");

const seedPermissions = async () => {
    try {
        // Define permissions
        const permissions = [
            // User permissions
            { name: 'users:read', description: 'View users', resource: 'users', action: 'read' },
            { name: 'users:create', description: 'Create new users', resource: 'users', action: 'create' },
            { name: 'users:update', description: 'Update user information', resource: 'users', action: 'update' },
            { name: 'users:delete', description: 'Delete users', resource: 'users', action: 'delete' },
            { name: 'users:manage', description: 'Full user management', resource: 'users', action: 'manage' },
            
            // Post permissions
            { name: 'posts:read', description: 'View posts', resource: 'posts', action: 'read' },
            { name: 'posts:create', description: 'Create new posts', resource: 'posts', action: 'create' },
            { name: 'posts:update', description: 'Update posts', resource: 'posts', action: 'update' },
            { name: 'posts:delete', description: 'Delete posts', resource: 'posts', action: 'delete' },
            { name: 'posts:manage', description: 'Full post management', resource: 'posts', action: 'manage' },
            
            // Comment permissions
            { name: 'comments:read', description: 'View comments', resource: 'comments', action: 'read' },
            { name: 'comments:create', description: 'Create comments', resource: 'comments', action: 'create' },
            { name: 'comments:update', description: 'Update comments', resource: 'comments', action: 'update' },
            { name: 'comments:delete', description: 'Delete comments', resource: 'comments', action: 'delete' },
            { name: 'comments:manage', description: 'Full comment management', resource: 'comments', action: 'manage' },
            
            // Settings permissions
            { name: 'settings:read', description: 'View settings', resource: 'settings', action: 'read' },
            { name: 'settings:update', description: 'Update settings', resource: 'settings', action: 'update' },
            { name: 'settings:manage', description: 'Full settings management', resource: 'settings', action: 'manage' },
            
            // Role & Permission management
            { name: 'roles:read', description: 'View roles', resource: 'roles', action: 'read' },
            { name: 'roles:create', description: 'Create roles', resource: 'roles', action: 'create' },
            { name: 'roles:update', description: 'Update roles', resource: 'roles', action: 'update' },
            { name: 'roles:delete', description: 'Delete roles', resource: 'roles', action: 'delete' },
            { name: 'roles:manage', description: 'Full role management', resource: 'roles', action: 'manage' },
        ];

        // Clear existing permissions
        await Permission.deleteMany({});
        console.log('Cleared existing permissions');

        // Insert permissions
        const createdPermissions = await Permission.insertMany(permissions);
        console.log(`Created ${createdPermissions.length} permissions`);

        return createdPermissions;
    } catch (error) {
        console.error('Error seeding permissions:', error);
        throw error;
    }
};

const seedRoles = async () => {
    try {
        // Get all permissions
        const allPermissions = await Permission.find({});

        // Define roles with their permissions
        const adminPermissions = allPermissions.map(p => p._id);
        
        const studentPermissions = allPermissions
            .filter(p => 
                p.resource === 'posts' && ['read', 'create', 'update'].includes(p.action) ||
                p.resource === 'comments' && ['read', 'create', 'update'].includes(p.action) ||
                p.name === 'users:read'
            )
            .map(p => p._id);
        
        const visitorPermissions = allPermissions
            .filter(p => 
                p.action === 'read' && ['posts', 'comments'].includes(p.resource)
            )
            .map(p => p._id);

        const roles = [
            {
                name: 'Admin',
                description: 'Full system access with all permissions',
                permissions: adminPermissions,
                isActive: true
            },
            {
                name: 'Student',
                description: 'Can create and manage own content',
                permissions: studentPermissions,
                isActive: true
            },
            {
                name: 'Visitor',
                description: 'Read-only access to public content',
                permissions: visitorPermissions,
                isActive: true
            }
        ];

        // Clear existing roles
        await Role.deleteMany({});
        console.log('Cleared existing roles');

        // Insert roles
        const createdRoles = await Role.insertMany(roles);
        console.log(`Created ${createdRoles.length} roles`);

        // Display role-permission mapping
        for (const role of createdRoles) {
            const populatedRole = await Role.findById(role._id).populate('permissions');
            console.log(`\nRole: ${populatedRole.name}`);
            console.log(`Permissions: ${populatedRole.permissions.map(p => p.name).join(', ')}`);
        }

        return createdRoles;
    } catch (error) {
        console.error('Error seeding roles:', error);
        throw error;
    }
};

const seedAll = async () => {
    try {
        console.log('\n=== Starting Permissions & Roles Seeding ===\n');
        
        await seedPermissions();
        await seedRoles();
        
        console.log('\n=== Seeding Completed Successfully ===\n');
    } catch (error) {
        console.error('Seeding failed:', error);
        throw error;
    }
};

module.exports = {
    seedPermissions,
    seedRoles,
    seedAll
};
