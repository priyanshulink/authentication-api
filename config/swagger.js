const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Authentication & SSO API',
            version: '1.0.0',
            description: `
# Enterprise Authentication System

A comprehensive authentication and authorization API with the following features:

## 🔐 Core Features
- JWT Authentication (Access + Refresh Tokens)
- RS256 Token Signing for SSO
- Email Verification
- Password Reset
- Two-Factor Authentication (TOTP)
- Rate Limiting & Account Lockout
- Role-Based Access Control (RBAC)
- Permission-Based Authorization
- Single Sign-On (OAuth2)
- Audit Logging

## 🚀 API Endpoints
- **/auth** - Authentication (login, signup, 2FA)
- **/oauth** - SSO & OAuth2 flows
- **/audit** - Audit logs & monitoring
            `,
            contact: {
                name: 'API Support',
                email: 'support@yourapp.com'
            }
        },
        servers: [
            {
                url: 'http://localhost:4000',
                description: 'Development server'
            },
            {
                url: 'https://api.yourapp.com',
                description: 'Production server'
            }
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                    description: 'Enter your JWT access token'
                }
            },
            schemas: {
                User: {
                    type: 'object',
                    properties: {
                        _id: { type: 'string' },
                        name: { type: 'string' },
                        email: { type: 'string' },
                        role: { type: 'object' },
                        isEmailVerified: { type: 'boolean' },
                        twoFactorEnabled: { type: 'boolean' },
                        createdAt: { type: 'string', format: 'date-time' }
                    }
                },
                TokenResponse: {
                    type: 'object',
                    properties: {
                        success: { type: 'boolean' },
                        accessToken: { type: 'string' },
                        message: { type: 'string' }
                    }
                },
                ErrorResponse: {
                    type: 'object',
                    properties: {
                        success: { type: 'boolean', example: false },
                        message: { type: 'string' }
                    }
                }
            }
        },
        tags: [
            {
                name: 'Authentication',
                description: 'User authentication endpoints (login, signup, 2FA)'
            },
            {
                name: 'Email',
                description: 'Email verification and password reset'
            },
            {
                name: 'OAuth2/SSO',
                description: 'Single Sign-On and OAuth2 endpoints'
            },
            {
                name: 'Audit Logs',
                description: 'Audit logging and monitoring'
            },
            {
                name: 'Two-Factor',
                description: '2FA management endpoints'
            },
            {
                name: 'Client Management',
                description: 'OAuth2 client registration and management'
            }
        ]
    },
    apis: ['./routes/*.js', './controller/*.js']
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = {
    swaggerUi,
    swaggerSpec
};
