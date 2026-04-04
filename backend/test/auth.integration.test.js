const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const mongoose = require('mongoose');
const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');

process.env.NODE_ENV = 'test';
process.env.APP_NAME = 'continental-id-auth-test';
process.env.MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/continental_dashboard_test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret-123456789012345678901234';
process.env.REFRESH_TOKEN_SECRET =
  process.env.REFRESH_TOKEN_SECRET || 'test-refresh-secret-12345678901234567890';
process.env.ALLOW_LOCALHOST_ORIGINS = 'true';
process.env.TRUST_PROXY = '1';

const { app } = require('../server');
const User = require('../models/User');

const TEST_ORIGIN = 'http://localhost:3000';

const sha256 = (value) =>
  crypto.createHash('sha256').update(String(value || '')).digest('hex');
const getRefreshCookie = (response) =>
  response.headers['set-cookie']?.find((value) => value.startsWith('refreshToken=')) || '';

const createVerifiedUser = async ({
  email = 'verified@example.com',
  username = 'verified.user',
  password = 'StrongPass1',
  displayName = 'Verified User',
} = {}) => {
  const user = new User({
    email,
    username,
    displayName,
    password,
    isVerified: true,
  });
  await user.save();
  return user;
};

let mongoServer;

test.before(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri(), {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
  });
});

test.after(async () => {
  await mongoose.disconnect();
  if (mongoServer) {
    await mongoServer.stop();
  }
});

test.beforeEach(async () => {
  await mongoose.connection.db.dropDatabase();
});

test('register creates an unverified account and blocks login until verification', async () => {
  const response = await request(app)
    .post('/api/auth/register')
    .set('Origin', TEST_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .send({
      email: 'new.user@example.com',
      username: 'new.user',
      displayName: 'New User',
      password: 'StrongPass1',
    });

  assert.equal(response.status, 201);
  assert.equal(response.body.authenticated, false);
  assert.equal(response.body.requiresVerification, true);

  const createdUser = await User.findOne({ email: 'new.user@example.com' }).lean();
  assert.ok(createdUser);
  assert.equal(createdUser.isVerified, false);
  assert.ok(createdUser.verificationToken);

  const loginResponse = await request(app)
    .post('/api/auth/login')
    .set('Origin', TEST_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .send({
      identifier: 'new.user',
      password: 'StrongPass1',
    });

  assert.equal(loginResponse.status, 403);
  assert.equal(loginResponse.body.authenticated, false);
  assert.equal(loginResponse.body.requiresVerification, true);
});

test('verify-email accepts a valid token and enables subsequent sign-in', async () => {
  const rawToken = 'verify-token-123';
  const user = await createVerifiedUser({
    email: 'needs.verify@example.com',
    username: 'needs.verify',
  });

  user.isVerified = false;
  user.verificationToken = sha256(rawToken);
  user.verificationTokenExpires = new Date(Date.now() + 60_000);
  await user.save();

  const verifyResponse = await request(app)
    .get('/api/auth/verify-email')
    .set('Origin', TEST_ORIGIN)
    .query({ token: rawToken });

  assert.equal(verifyResponse.status, 200);
  assert.match(verifyResponse.body.message, /Email verified/i);

  const refreshedUser = await User.findById(user._id).lean();
  assert.equal(refreshedUser.isVerified, true);
  assert.equal(refreshedUser.verificationToken, '');
});

test('verified users can log in, read their profile, and refresh their session', async () => {
  await createVerifiedUser();
  const loginResponse = await request(app)
    .post('/api/auth/login')
    .set('Origin', TEST_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .send({
      identifier: 'verified.user',
      password: 'StrongPass1',
      deviceLabel: 'Integration Browser',
    });

  assert.equal(loginResponse.status, 200);
  assert.equal(loginResponse.body.authenticated, true);
  assert.ok(loginResponse.body.token);
  const refreshCookie = getRefreshCookie(loginResponse);
  assert.ok(refreshCookie);

  const accessToken = loginResponse.body.token;

  const meResponse = await request(app)
    .get('/api/auth/me')
    .set('Authorization', `Bearer ${accessToken}`);

  assert.equal(meResponse.status, 200);
  assert.equal(meResponse.body.user.email, 'verified@example.com');

  const refreshResponse = await request(app)
    .post('/api/auth/refresh_token')
    .set('Origin', TEST_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', refreshCookie)
    .send({});
  assert.equal(refreshResponse.status, 200);
  assert.equal(refreshResponse.body.message, 'Session refreshed.');
  assert.ok(refreshResponse.body.accessToken);
  assert.ok(
    refreshResponse.headers['set-cookie']?.some((value) => value.startsWith('refreshToken='))
  );
});

test('request-password-reset sets a reset token and reset-password updates the password', async () => {
  await createVerifiedUser({
    email: 'reset.user@example.com',
    username: 'reset.user',
    password: 'StrongPass1',
  });

  const requestResponse = await request(app)
    .post('/api/auth/request-password-reset')
    .set('Origin', TEST_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .send({ identifier: 'reset.user@example.com' });

  assert.equal(requestResponse.status, 200);

  const requestedUser = await User.findOne({ email: 'reset.user@example.com' });
  assert.ok(requestedUser.passwordResetToken);
  assert.ok(requestedUser.passwordResetTokenExpires);

  const rawResetToken = 'known-reset-token';
  requestedUser.passwordResetToken = sha256(rawResetToken);
  requestedUser.passwordResetTokenExpires = new Date(Date.now() + 60_000);
  await requestedUser.save();

  const resetResponse = await request(app)
    .post('/api/auth/reset-password')
    .set('Origin', TEST_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .send({
      token: rawResetToken,
      newPassword: 'NewStrongPass2',
    });

  assert.equal(resetResponse.status, 200);
  assert.match(resetResponse.body.message, /Password reset successful/i);

  const oldLoginResponse = await request(app)
    .post('/api/auth/login')
    .set('Origin', TEST_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .send({
      identifier: 'reset.user',
      password: 'StrongPass1',
    });
  assert.equal(oldLoginResponse.status, 400);

  const newLoginResponse = await request(app)
    .post('/api/auth/login')
    .set('Origin', TEST_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .send({
      identifier: 'reset.user',
      password: 'NewStrongPass2',
    });
  assert.equal(newLoginResponse.status, 200);
  assert.equal(newLoginResponse.body.authenticated, true);
});

test('revoking all sessions invalidates refresh cookies and access tokens on the next check', async () => {
  await createVerifiedUser({
    email: 'sessions@example.com',
    username: 'sessions.user',
  });

  const loginResponse = await request(app)
    .post('/api/auth/login')
    .set('Origin', TEST_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .send({
      identifier: 'sessions.user',
      password: 'StrongPass1',
    });
  const accessToken = loginResponse.body.token;
  const refreshCookie = getRefreshCookie(loginResponse);

  const revokeResponse = await request(app)
    .delete('/api/auth/sessions')
    .set('Authorization', `Bearer ${accessToken}`)
    .send({});

  assert.equal(revokeResponse.status, 200);
  assert.equal(revokeResponse.body.forceRelogin, true);

  const meResponse = await request(app)
    .get('/api/auth/me')
    .set('Authorization', `Bearer ${accessToken}`);
  assert.equal(meResponse.status, 401);

  const refreshResponse = await request(app)
    .post('/api/auth/refresh_token')
    .set('Origin', TEST_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .set('Cookie', refreshCookie)
    .send({});
  assert.equal(refreshResponse.status, 200);
  assert.equal(refreshResponse.body.authenticated, false);
});
