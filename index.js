const express = require('express');
const app = express();

require("dotenv").config();
const PORT = process.env.PORT || 4000;
app.use(express.json());

// Swagger documentation
const { swaggerUi, swaggerSpec } = require('./config/swagger');
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'Authentication API Documentation'
}));

// cookie-parser middleware: parses cookies on incoming requests
const cookieParser = require('cookie-parser');
app.use(cookieParser());
//db ko import kiya aur connect kiya 
require("./config/database").dbConnect();
//route ko import and mount
const user = require("./routes/user");
app.use("/api/v1",user);

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

//activate
app.listen(PORT,()=>{
    console.log(`app is listening at ${PORT}`);
    console.log(`API Documentation available at: http://localhost:${PORT}/api-docs`);
})