const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');

process.env.NODE_ENV = 'test';
process.env.APP_NAME = 'continental-id-auth-stepcast-test';
process.env.MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/continental_dashboard_stepcast_test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret-123456789012345678901234';
process.env.REFRESH_TOKEN_SECRET =
  process.env.REFRESH_TOKEN_SECRET || 'test-refresh-secret-12345678901234567890';
process.env.ALLOW_LOCALHOST_ORIGINS = 'true';
process.env.TRUST_PROXY = '1';

const { app } = require('../server');
const User = require('../models/User');

const STEPCAST_PAGES_ORIGIN = 'https://pclaystation.github.io';

const getRefreshCookie = (response) =>
  response.headers['set-cookie']?.find((value) => value.startsWith('refreshToken=')) || '';

let mongoServer;

test.before(async () => {
  mongoServer = await MongoMemoryServer.create({
    instance: {
      launchTimeout: 30_000,
    },
  });
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

test('StepCast-style clients can register with email/password, then log in and refresh through a proxy', async () => {
  const email = 'stepcast.user@example.com';
  const password = 'StrongPass1';

  const registerResponse = await request(app)
    .post('/api/auth/register')
    .set('Origin', STEPCAST_PAGES_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .send({
      email,
      password,
    });

  assert.equal(registerResponse.status, 201);
  assert.equal(registerResponse.body.authenticated, false);
  assert.equal(registerResponse.body.requiresVerification, true);

  const createdUser = await User.findOne({ email });
  assert.ok(createdUser);
  assert.equal(createdUser.isVerified, false);

  // StepCast forwards Continental auth but does not manage email verification itself.
  createdUser.isVerified = true;
  createdUser.verificationToken = '';
  createdUser.verificationTokenExpires = null;
  await createdUser.save();

  const loginResponse = await request(app)
    .post('/api/auth/login')
    .set('Origin', STEPCAST_PAGES_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .send({
      email,
      password,
      deviceLabel: 'StepCast proxy client',
    });

  assert.equal(loginResponse.status, 200);
  assert.equal(loginResponse.body.authenticated, true);
  assert.ok(loginResponse.body.accessToken);

  const accessToken = loginResponse.body.accessToken;
  const refreshCookie = getRefreshCookie(loginResponse);
  assert.ok(refreshCookie);

  const meResponse = await request(app)
    .get('/api/auth/me')
    .set('Authorization', `Bearer ${accessToken}`);

  assert.equal(meResponse.status, 200);
  assert.equal(meResponse.body.user.email, email);

  const refreshResponse = await request(app)
    .post('/api/auth/refresh_token')
    .set('Origin', STEPCAST_PAGES_ORIGIN)
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
