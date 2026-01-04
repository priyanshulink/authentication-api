# 🔐 Enterprise Authentication System

Complete authentication and authorization system with JWT tokens, 2FA, OAuth2/SSO, audit logging, and comprehensive security features.

## 📋 Table of Contents
- [Features](#features)
- [Quick Start](#quick-start)
- [API Documentation](#api-documentation)
- [Architecture](#architecture)
- [Security Features](#security-features)
- [Testing](#testing)
- [Deployment](#deployment)
- [Documentation](#documentation)

---

## ✨ Features

### Core Authentication
- ✅ **JWT Authentication** - Access tokens (15 min) + Refresh tokens (7 days)
- ✅ **User Registration** - Signup with email verification
- ✅ **Secure Login** - bcrypt password hashing (10 rounds)
- ✅ **Mobile OTP Authentication** - SMS-based login with OTP
- ✅ **Token Refresh** - Automatic token renewal
- ✅ **Logout** - Token revocation with blacklist

### Advanced Security
- ✅ **Two-Factor Authentication (2FA)** - TOTP with Google Authenticator
- ✅ **Recovery Codes** - 10 one-time backup codes for 2FA
- ✅ **Email Verification** - Account activation via email
- ✅ **Password Reset** - Secure password recovery flow
- ✅ **Rate Limiting** - 5 login attempts per 15 minutes
- ✅ **Account Lockout** - Auto-lock after 5 failed attempts (30 min)

### Authorization
- ✅ **Role-Based Access Control (RBAC)** - Admin, Teacher, Student roles
- ✅ **Permission-Based Authorization** - Fine-grained access control
- ✅ **Dynamic Permissions** - users:manage, oauth:clients, etc.

### OAuth2 & SSO
- ✅ **OAuth2 Authorization Code Flow** - Standard SSO implementation
- ✅ **RS256 JWT Tokens** - Public/private key cryptography
- ✅ **Client Management** - Register and manage OAuth apps
- ✅ **JWKS Endpoint** - JSON Web Key Set for token validation
- ✅ **Scope Support** - read, write, admin scopes

### Audit Logging & Monitoring
- ✅ **Comprehensive Audit Logs** - 21 event types tracked
- ✅ **IP & User-Agent Tracking** - Complete request metadata
- ✅ **Security Event Monitoring** - Failed logins, locks, denials
- ✅ **Admin Dashboard** - View logs, statistics, user activity
- ✅ **Retention Policy** - Clean old logs automatically

### Testing & Documentation
- ✅ **Security Test Suite** - 16 comprehensive tests
- ✅ **API Documentation** - Swagger/OpenAPI 3.0
- ✅ **Flow Diagrams** - Visual authentication flows
- ✅ **Testing Guide** - Complete testing documentation

---

## 🚀 Quick Start

### Prerequisites
- Node.js 14+ 
- MongoDB Atlas account (or local MongoDB)
- Gmail account (for email features)

### 1. Installation

```bash
# Clone repository
git clone <your-repo-url>
cd authentication

# Install dependencies
npm install
```

### 2. Environment Configuration

Create `.env` file in the `authentication` folder:

```env
# Server
PORT=4000
NODE_ENV=development

# Database
MONGODB_URL=mongodb+srv://username:password@cluster.mongodb.net/auth-db

# JWT Secrets
ACCESS_TOKEN_SECRET=your-super-secret-access-token-key-min-32-chars
REFRESH_TOKEN_SECRET=your-super-secret-refresh-token-key-min-32-chars

# RSA Keys for OAuth2 (generate using generateKeys.js)
JWT_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nYourPrivateKey\n-----END PRIVATE KEY-----
JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\nYourPublicKey\n-----END PUBLIC KEY-----

# Email Configuration (Gmail)
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-specific-password

# SMS Configuration (Optional - for production)
# TWILIO_ACCOUNT_SID=your-twilio-account-sid
# TWILIO_AUTH_TOKEN=your-twilio-auth-token
# TWILIO_PHONE_NUMBER=+1234567890
# OR use AWS SNS, MSG91, or any SMS provider

# Frontend URL (for CORS and email links)
FRONTEND_URL=http://localhost:3000
```

### 3. Generate RSA Keys

```bash
cd authentication
node generateKeys.js
```

Copy the generated keys to your `.env` file.

### 4. Seed Database (Optional)

```bash
node seedDatabase.js
```

This creates:
- 3 Roles: Admin, Teacher, Student
- 3 Permissions: users:manage, oauth:clients, content:create
- Default admin user

### 5. Start Server

```bash
npm start
```

Server runs at: **http://localhost:4000**

### 6. Access Documentation

Open in browser: **http://localhost:4000/api-docs**

---

## 📚 API Documentation

### Interactive API Explorer
- **Swagger UI**: http://localhost:4000/api-docs
- Test endpoints directly in browser
- See request/response examples
- Authentication with Bearer tokens

### Base URL
```
http://localhost:4000/api/v1
```

### Quick Reference

#### Authentication
```bash
# Signup
POST /api/v1/signup
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecurePass123!",
  "roleName": "Student"
}

# Login
POST /api/v1/login
{
  "email": "john@example.com",
  "password": "SecurePass123!"
}

# Refresh Token
POST /api/v1/refresh
# (uses HTTP-only cookie automatically)

# Logout
POST /api/v1/logout
{
  "refreshToken": "your-refresh-token"
}
```

#### Two-Factor Authentication
```bash
# Setup 2FA
POST /api/v1/2fa/setup
Authorization: Bearer YOUR_TOKEN

# Verify and Enable
POST /api/v1/2fa/verify-setup
{
  "token": "123456"
}

# Login with 2FA
POST /api/v1/login-2fa
{
  "tempToken": "temp-token-from-login",
  "token": "123456"
}
```

#### Mobile OTP Authentication
```bash
# Register mobile number (authenticated users)
POST /api/v1/mobile/register
Authorization: Bearer YOUR_TOKEN
{
  "mobile": "9876543210",
  "countryCode": "+91"
}

# Verify mobile OTP
POST /api/v1/mobile/verify
Authorization: Bearer YOUR_TOKEN
{
  "otp": "123456"
}

# Send login OTP
POST /api/v1/mobile/send-login-otp
{
  "mobile": "9876543210",
  "countryCode": "+91"
}

# Login with mobile OTP
POST /api/v1/mobile/login
{
  "mobile": "9876543210",
  "otp": "123456",
  "countryCode": "+91"
}

# Resend OTP
POST /api/v1/mobile/resend-otp
{
  "mobile": "9876543210",
  "countryCode": "+91"
}
```

#### OAuth2 Flow
```bash
# 1. Authorize (redirect to this URL)
GET /api/v1/oauth/authorize?response_type=code&client_id=xxx&redirect_uri=xxx&scope=read

# 2. Exchange code for token
POST /api/v1/oauth/token
{
  "grant_type": "authorization_code",
  "code": "auth-code",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "redirect_uri": "http://localhost:3000/callback"
}
```

#### Audit Logs
```bash
# Get your own logs
GET /api/v1/audit/my-logs
Authorization: Bearer YOUR_TOKEN

# Get all logs (Admin only)
GET /api/v1/audit/logs?action=LOGIN&limit=100
Authorization: Bearer ADMIN_TOKEN

# Security events (Admin only)
GET /api/v1/audit/security-events
Authorization: Bearer ADMIN_TOKEN
```

---

## 🏗️ Architecture

### Project Structure
```
authentication/
├── config/
│   ├── database.js          # MongoDB connection
│   └── swagger.js           # OpenAPI configuration
├── controller/
│   ├── Auth.js              # Login/signup
│   ├── RefreshToken.js      # Token refresh/logout
│   ├── EmailVerification.js # Email verify/password reset
│   ├── MobileOTP.js         # Mobile OTP authentication
│   ├── TwoFactor.js         # 2FA setup/verify
│   ├── TwoFactor.js         # 2FA management
│   ├── OAuth.js             # OAuth2 flow
│   ├── ClientManagement.js  # OAuth client CRUD
│   ├── AccountLock.js       # Lock/unlock accounts
│   └── AuditLogController.js # Audit log viewing
├── middlewares/
│   ├── auth.js              # JWT verification
│   ├── rateLimiter.js       # Rate limiting
│   └── permissions.js       # Permission checks
├── model/
│   ├── User.js              # User schema
│   ├── Role.js              # Role schema
│   ├── Permission.js        # Permission schema
│   ├── TokenBlacklist.js    # Revoked tokens
│   ├── OAuthClient.js       # OAuth client apps
│   ├── OAuthCode.js         # Authorization codes
│   └── AuditLog.js          # Audit log events
├── routes/
│   └── user.js              # All API routes
├── utils/
│   ├── auditLogger.js       # Centralized logging
│   ├── emailService.js      # Email sending
│   └── smsService.js        # SMS/OTP sending
├── tests/
│   └── security.test.js     # Security test suite
├── docs/
│   ├── TESTING_GUIDE.md     # Testing documentation
│   ├── AUTH_FLOWS.md        # Flow diagrams
│   └── PHASE_9_10_COMPLETE.md # Implementation details
├── index.js                 # Application entry point
├── generateKeys.js          # RSA key generator
└── seedDatabase.js          # Database seeding
```

### Tech Stack
- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose
- **Authentication**: JWT (jsonwebtoken)
- **Password Hashing**: bcrypt
- **2FA**: speakeasy, qrcode
- **Email**: nodemailer
- **Rate Limiting**: express-rate-limit
- **Testing**: Jest, Supertest
- **Documentation**: Swagger UI, OpenAPI 3.0

---

## 🔒 Security Features

### Token Security
- **HS256 for access/refresh** - Symmetric signing
- **RS256 for OAuth** - Asymmetric signing (public/private keys)
- **Short-lived access tokens** - 15 minutes
- **Long-lived refresh tokens** - 7 days
- **Token blacklist** - Prevent reuse after logout
- **Automatic rotation** - New tokens on refresh

### Password Security
- **bcrypt hashing** - 10 salt rounds
- **Password strength** - Min 8 chars, uppercase, number, special
- **Reset tokens** - Cryptographically random, 1-hour expiry
- **One-time use** - Reset tokens work only once

### Rate Limiting
- **Login**: 5 attempts per 15 minutes per IP
- **2FA**: 5 attempts per 15 minutes per IP
- **Password Reset**: 3 requests per hour per IP
- **Signup**: 3 registrations per hour per IP
- **General API**: 100 requests per 15 minutes per user

### Account Protection
- **Failed login tracking** - Count wrong password attempts
- **Automatic lockout** - Lock after 5 failed attempts
- **Time-based unlock** - Auto-unlock after 30 minutes
- **Admin override** - Manual unlock by administrators

### Audit Logging
All security events are logged with:
- **User ID** - Who performed the action
- **Action Type** - What happened (LOGIN, LOGOUT, etc.)
- **IP Address** - Request origin (proxy-aware)
- **User Agent** - Browser/client information
- **Status** - SUCCESS, FAILURE, or WARNING
- **Metadata** - Additional context (attempts remaining, etc.)
- **Timestamp** - When it occurred

### 21 Tracked Events
LOGIN, LOGIN_FAILED, LOGIN_2FA, LOGOUT, TOKEN_REFRESH, TOKEN_REVOKED, PASSWORD_RESET_REQUEST, PASSWORD_RESET_COMPLETE, TWO_FA_ENABLED, TWO_FA_DISABLED, ACCOUNT_LOCKED, ACCOUNT_UNLOCKED, EMAIL_VERIFICATION, OAUTH_AUTHORIZE, OAUTH_TOKEN_ISSUED, PERMISSION_DENIED, and more.

---

## 🧪 Testing

### Run All Tests
```bash
npm test
```

### Run Security Tests
```bash
npm run test:security
```

### Generate Coverage Report
```bash
npm run test:coverage
```

### Test Suites (16 tests)
1. ✅ Token Misuse (5 tests) - Invalid, tampered, malformed tokens
2. ✅ Expired Tokens (2 tests) - Access token expiration
3. ✅ Revoked Tokens (2 tests) - Logout and blacklist
4. ✅ Permission Bypass (3 tests) - Unauthorized access attempts
5. ✅ Rate Limiting (1 test) - Brute force prevention
6. ✅ Account Lockout (1 test) - Failed attempt protection
7. ✅ Password Reset (2 tests) - Secure recovery

### Manual Testing
See **[TESTING_GUIDE.md](authentication/TESTING_GUIDE.md)** for:
- cURL examples for all endpoints
- Test scenarios and attack vectors
- Troubleshooting guide
- CI/CD integration examples

---

## 🚀 Deployment

### Environment Variables
Ensure all production secrets are set:
- Strong JWT secrets (min 32 characters)
- Production MongoDB URL
- Gmail app-specific password
- Generated RSA key pair
- Correct FRONTEND_URL

### Production Checklist
- [ ] Environment variables configured
- [ ] MongoDB Atlas IP whitelist updated
- [ ] Gmail less secure apps enabled (or app password)
- [ ] CORS origins configured correctly
- [ ] Rate limits adjusted for production traffic
- [ ] Audit log cleanup scheduled (cron job)
- [ ] SSL/TLS certificates installed
- [ ] Security headers enabled (helmet)
- [ ] Error logging configured (winston/sentry)
- [ ] All tests passing

### Recommended Production Settings
```env
NODE_ENV=production
PORT=443
# Use strong secrets (32+ chars)
# Enable HTTPS
# Set secure cookie flags
```

### Database Indexes
Ensure these indexes exist for performance:
- `User.email` (unique)
- `AuditLog.userId + timestamp`
- `AuditLog.action + timestamp`
- `AuditLog.timestamp`
- `TokenBlacklist.token` (unique)
- `OAuthClient.clientId` (unique)

---

## 📖 Documentation

### Available Documentation
1. **[README.md](README.md)** - This file (overview)
2. **[TESTING_GUIDE.md](authentication/TESTING_GUIDE.md)** - Complete testing guide
3. **[AUTH_FLOWS.md](authentication/AUTH_FLOWS.md)** - Visual flow diagrams
4. **[PHASE_9_10_COMPLETE.md](authentication/PHASE_9_10_COMPLETE.md)** - Implementation details
5. **Swagger UI** - http://localhost:4000/api-docs

### Flow Diagrams
See [AUTH_FLOWS.md](authentication/AUTH_FLOWS.md) for Mermaid diagrams of:
- Basic Login Flow
- 2FA Login Flow
- Token Refresh Flow
- OAuth2 Authorization Code Flow
- Password Reset Flow
- Email Verification Flow
- Account Lockout Flow
- Permission-Based Access Control

---

## 🛠️ Development

### Add New Permission
```javascript
// 1. Add to model/Permission.js
const permission = await Permission.create({
  name: 'posts:delete',
  description: 'Delete any post'
});

// 2. Assign to role
const adminRole = await Role.findOne({ name: 'Admin' });
adminRole.permissions.push(permission._id);
await adminRole.save();

// 3. Protect route
router.delete('/posts/:id', 
  auth, 
  hasPermission('posts:delete'), 
  deletePost
);
```

### Add New Audit Event
```javascript
// 1. Add action type to model/AuditLog.js
action: {
  type: String,
  enum: ['LOGIN', 'LOGOUT', ..., 'YOUR_NEW_EVENT']
}

// 2. Use in controller
const { logEvent } = require('../utils/auditLogger');
await logEvent(req, userId, 'YOUR_NEW_EVENT', 'SUCCESS', { metadata });
```

### Custom Rate Limiting
```javascript
const customLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 requests
  message: 'Too many requests'
});

router.post('/endpoint', customLimiter, handler);
```

---

## 🤝 API Integration Examples

### React Frontend
```javascript
// auth.js
export const login = async (email, password) => {
  const res = await fetch('http://localhost:4000/api/v1/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include', // Include cookies
    body: JSON.stringify({ email, password })
  });
  return res.json();
};

export const apiCall = async (url, options = {}) => {
  const token = localStorage.getItem('accessToken');
  const res = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (res.status === 401) {
    // Token expired, refresh
    const refreshRes = await fetch('/api/v1/refresh', {
      method: 'POST',
      credentials: 'include'
    });
    if (refreshRes.ok) {
      const { accessToken } = await refreshRes.json();
      localStorage.setItem('accessToken', accessToken);
      return apiCall(url, options); // Retry
    }
  }
  return res;
};
```

### Mobile App (React Native)
```javascript
// Use AsyncStorage for tokens
import AsyncStorage from '@react-native-async-storage/async-storage';

const login = async (email, password) => {
  const res = await fetch('https://api.yourapp.com/api/v1/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const data = await res.json();
  await AsyncStorage.setItem('accessToken', data.accessToken);
  await AsyncStorage.setItem('refreshToken', data.refreshToken);
};
```

---

## 📊 Performance

### Expected Metrics
- **Login**: < 200ms
- **Token Refresh**: < 100ms
- **2FA Verification**: < 150ms
- **OAuth Token Exchange**: < 300ms
- **Audit Log Query**: < 50ms (with indexes)

### Optimization Tips
- Use MongoDB indexes on frequently queried fields
- Implement Redis for token blacklist (faster than MongoDB)
- Cache user roles/permissions
- Use connection pooling for database
- Enable compression (gzip)

---

## 🐛 Troubleshooting

### Common Issues

**Issue**: "Cannot find module 'swagger-jsdoc'"
```bash
npm install swagger-ui-express swagger-jsdoc
```

**Issue**: MongoDB connection failed
- Check `MONGODB_URL` in `.env`
- Verify IP whitelist in MongoDB Atlas
- Ensure network connectivity

**Issue**: Email not sending
- Use Gmail app-specific password (not regular password)
- Enable "Less secure app access" in Gmail
- Check `EMAIL_USER` and `EMAIL_PASS` in `.env`

**Issue**: 2FA QR code not working
- Ensure system time is synchronized
- Try manual entry with secret key
- Check TOTP settings (30s window, 6 digits)

**Issue**: OAuth tokens invalid
- Regenerate RSA keys with `generateKeys.js`
- Ensure `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` in `.env`
- Use RS256 algorithm for OAuth tokens

---

## 📜 License

MIT License - Feel free to use in your projects

---

## 👨‍💻 Author

Development Team - 2024-2026

---

## 🎯 Future Enhancements

- [ ] WebAuthn/FIDO2 support
- [ ] Social login (Google, Facebook, GitHub)
- [ ] Multi-factor authentication (SMS, email)
- [ ] Session management dashboard
- [ ] Advanced analytics and reporting
- [ ] Webhook support for events
- [ ] API versioning (v2)
- [ ] GraphQL API
- [ ] Microservices architecture
- [ ] Kubernetes deployment configs

---

## 📞 Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Review documentation in `/docs` folder
- Check Swagger UI for API reference

---

**Version**: 1.0.0  
**Last Updated**: January 4, 2026  
**Status**: Production Ready ✅
