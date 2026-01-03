/**
 * Security Tests for Authentication System
 * Tests token misuse, expiration, revocation, and security vulnerabilities
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');

// Note: Replace with your actual server URL
const BASE_URL = 'http://localhost:4000/api/v1';

describe('🔐 Security Tests - Token Misuse', () => {
    let validToken;
    let userId;

    beforeAll(async () => {
        // Create a test user and get valid token
        const signupRes = await request(BASE_URL)
            .post('/signup')
            .send({
                name: 'Test User',
                email: `test${Date.now()}@security.test`,
                password: 'SecurePass123!',
                roleName: 'Student'
            });

        const loginRes = await request(BASE_URL)
            .post('/login')
            .send({
                email: signupRes.body.email,
                password: 'SecurePass123!'
            });

        validToken = loginRes.body.accessToken;
        userId = jwt.decode(validToken).userId;
    });

    test('Should reject invalid token format', async () => {
        const res = await request(BASE_URL)
            .get('/test')
            .set('Authorization', 'Bearer invalid_token_12345');

        expect(res.status).toBe(401);
        expect(res.body.success).toBe(false);
        expect(res.body.message).toContain('Token expired or invalid');
    });

    test('Should reject token without Bearer prefix', async () => {
        const res = await request(BASE_URL)
            .get('/test')
            .set('Authorization', validToken);

        expect(res.status).toBe(401);
        expect(res.body.success).toBe(false);
    });

    test('Should reject request without token', async () => {
        const res = await request(BASE_URL)
            .get('/test');

        expect(res.status).toBe(401);
        expect(res.body.success).toBe(false);
        expect(res.body.message).toContain('No token provided');
    });

    test('Should reject tampered token', async () => {
        // Tamper with the token by changing last character
        const tamperedToken = validToken.slice(0, -1) + 'X';

        const res = await request(BASE_URL)
            .get('/test')
            .set('Authorization', `Bearer ${tamperedToken}`);

        expect(res.status).toBe(401);
        expect(res.body.success).toBe(false);
    });

    test('Should reject token with modified payload', async () => {
        const decoded = jwt.decode(validToken);
        const modifiedPayload = { ...decoded, role: 'Admin' };
        
        // Try to create token with wrong secret
        const fakeToken = jwt.sign(modifiedPayload, 'wrong_secret');

        const res = await request(BASE_URL)
            .get('/test')
            .set('Authorization', `Bearer ${fakeToken}`);

        expect(res.status).toBe(401);
        expect(res.body.success).toBe(false);
    });
});

describe('⏰ Security Tests - Expired Tokens', () => {
    test('Should reject expired token', async () => {
        // Create an already expired token
        const expiredToken = jwt.sign(
            {
                userId: 'test_user_id',
                role: 'Student'
            },
            process.env.ACCESS_TOKEN_SECRET || 'test_secret',
            { expiresIn: '-1h' } // Expired 1 hour ago
        );

        const res = await request(BASE_URL)
            .get('/test')
            .set('Authorization', `Bearer ${expiredToken}`);

        expect(res.status).toBe(401);
        expect(res.body.success).toBe(false);
        expect(res.body.message).toContain('Token expired or invalid');
    });

    test('Should accept valid non-expired token', async () => {
        // Create a valid token
        const validToken = jwt.sign(
            {
                userId: 'test_user_id',
                role: { name: 'Student' }
            },
            process.env.ACCESS_TOKEN_SECRET || 'test_secret',
            { expiresIn: '15m' }
        );

        const res = await request(BASE_URL)
            .get('/test')
            .set('Authorization', `Bearer ${validToken}`);

        // May fail if user doesn't exist, but token should be valid
        expect([200, 404]).toContain(res.status);
    });
});

describe('🚫 Security Tests - Revoked Tokens', () => {
    let token;
    let refreshToken;

    beforeAll(async () => {
        // Create user and login
        const email = `revoke${Date.now()}@security.test`;
        await request(BASE_URL)
            .post('/signup')
            .send({
                name: 'Revoke Test',
                email,
                password: 'RevokePass123!',
                roleName: 'Student'
            });

        const loginRes = await request(BASE_URL)
            .post('/login')
            .send({ email, password: 'RevokePass123!' });

        token = loginRes.body.accessToken;
        refreshToken = loginRes.headers['set-cookie']
            ?.find(cookie => cookie.startsWith('refreshToken='))
            ?.split(';')[0]
            ?.split('=')[1];
    });

    test('Should successfully logout and revoke token', async () => {
        const res = await request(BASE_URL)
            .post('/logout')
            .set('Authorization', `Bearer ${token}`)
            .send({ refreshToken });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.message).toContain('Logged out successfully');
    });

    test('Should reject using revoked token after logout', async () => {
        const res = await request(BASE_URL)
            .get('/test')
            .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(401);
        expect(res.body.success).toBe(false);
        expect(res.body.message).toContain('revoked');
    });
});

describe('🛡️ Security Tests - Permission Bypass Attempts', () => {
    let studentToken;

    beforeAll(async () => {
        const email = `student${Date.now()}@security.test`;
        await request(BASE_URL)
            .post('/signup')
            .send({
                name: 'Student User',
                email,
                password: 'StudentPass123!',
                roleName: 'Student'
            });

        const loginRes = await request(BASE_URL)
            .post('/login')
            .send({ email, password: 'StudentPass123!' });

        studentToken = loginRes.body.accessToken;
    });

    test('Student should NOT access admin-only route', async () => {
        const res = await request(BASE_URL)
            .get('/admin')
            .set('Authorization', `Bearer ${studentToken}`);

        expect(res.status).toBe(403);
        expect(res.body.success).toBe(false);
        expect(res.body.message).toContain('permission');
    });

    test('Student should NOT unlock accounts (admin permission)', async () => {
        const res = await request(BASE_URL)
            .post('/account/unlock')
            .set('Authorization', `Bearer ${studentToken}`)
            .send({ email: 'some@user.com' });

        expect(res.status).toBe(403);
        expect(res.body.success).toBe(false);
    });

    test('Student should NOT register OAuth clients', async () => {
        const res = await request(BASE_URL)
            .post('/oauth/clients')
            .set('Authorization', `Bearer ${studentToken}`)
            .send({
                name: 'Evil App',
                redirectUris: ['http://evil.com/callback']
            });

        expect(res.status).toBe(403);
        expect(res.body.success).toBe(false);
    });
});

describe('🔒 Security Tests - Rate Limiting', () => {
    test('Should rate limit login attempts', async () => {
        const email = 'ratelimit@test.com';
        const password = 'wrong_password';

        // Make 6 failed login attempts (limit is 5)
        for (let i = 0; i < 6; i++) {
            const res = await request(BASE_URL)
                .post('/login')
                .send({ email, password });

            if (i < 5) {
                // First 5 should process (may fail with 401, but not rate limited)
                expect([400, 401, 423]).toContain(res.status);
            } else {
                // 6th request should be rate limited
                expect(res.status).toBe(429);
            }
        }
    });
});

describe('🔐 Security Tests - Account Lockout', () => {
    let email;
    const correctPassword = 'CorrectPass123!';

    beforeAll(async () => {
        email = `lockout${Date.now()}@security.test`;
        await request(BASE_URL)
            .post('/signup')
            .send({
                name: 'Lockout Test',
                email,
                password: correctPassword,
                roleName: 'Student'
            });
    });

    test('Should lock account after 5 failed login attempts', async () => {
        // Make 5 failed attempts
        for (let i = 0; i < 5; i++) {
            await request(BASE_URL)
                .post('/login')
                .send({ email, password: 'wrong_password' });
        }

        // 6th attempt with CORRECT password should still be blocked
        const res = await request(BASE_URL)
            .post('/login')
            .send({ email, password: correctPassword });

        expect(res.status).toBe(423);
        expect(res.body.success).toBe(false);
        expect(res.body.message).toContain('locked');
    });
});

describe('🔑 Security Tests - Password Reset Security', () => {
    test('Should not reveal if email exists on password reset', async () => {
        const res = await request(BASE_URL)
            .post('/forgot-password')
            .send({ email: 'nonexistent@test.com' });

        // Should return 200 even if user doesn't exist (security by obscurity)
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.message).not.toContain('not found');
    });

    test('Should reject expired password reset token', async () => {
        // Try to reset with expired/invalid token
        const res = await request(BASE_URL)
            .post('/reset-password/invalid_expired_token')
            .send({ password: 'NewPass123!' });

        expect(res.status).toBe(400);
        expect(res.body.success).toBe(false);
        expect(res.body.message).toContain('Invalid or expired');
    });
});

module.exports = {
    // Export for CI/CD integration
    testSuite: 'Security Tests'
};
