// Standalone script to seed permissions and roles
require('dotenv').config();
const mongoose = require('mongoose');
const { seedAll } = require('./utils/seedPermissions');

const runSeeder = async () => {
    try {
        // Connect to database
        console.log('Connecting to database...');
        await mongoose.connect(process.env.MONGODB_URL);
        console.log('Database connected successfully\n');

        // Run seeder
        await seedAll();

        // Disconnect
        await mongoose.disconnect();
        console.log('Database connection closed');
        
        process.exit(0);
    } catch (error) {
        console.error('Seeding error:', error);
        await mongoose.disconnect();
        process.exit(1);
    }
};

runSeeder();
