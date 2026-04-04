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

test('sessions endpoint returns the current session and allows revoking it explicitly', async () => {
  await createVerifiedUser({
    email: 'current.session@example.com',
    username: 'current.session',
  });

  const loginResponse = await request(app)
    .post('/api/auth/login')
    .set('Origin', TEST_ORIGIN)
    .set('X-Forwarded-Proto', 'https')
    .send({
      identifier: 'current.session',
      password: 'StrongPass1',
      deviceLabel: 'MacBook Pro',
    });

  const accessToken = loginResponse.body.token;

  const sessionsResponse = await request(app)
    .get('/api/auth/sessions')
    .set('Authorization', `Bearer ${accessToken}`);

  assert.equal(sessionsResponse.status, 200);
  assert.ok(Array.isArray(sessionsResponse.body.sessions));
  assert.equal(sessionsResponse.body.sessions.length, 1);
  assert.equal(sessionsResponse.body.sessions[0].current, true);
  assert.equal(sessionsResponse.body.sessions[0].label, 'MacBook Pro');

  const revokeResponse = await request(app)
    .delete(`/api/auth/sessions/${encodeURIComponent(sessionsResponse.body.sessions[0].sid)}`)
    .set('Authorization', `Bearer ${accessToken}`)
    .send({});

  assert.equal(revokeResponse.status, 200);
  assert.equal(revokeResponse.body.revokedCurrentSession, true);
  assert.equal(revokeResponse.body.forceRelogin, true);
});

test('public profile directory and direct profile lookup only expose public accounts', async () => {
  const publicUser = await createVerifiedUser({
    email: 'public.user@example.com',
    username: 'public.user',
    displayName: 'Public User',
  });
  publicUser.profile.headline = 'Building cleaner auth systems';
  publicUser.profile.location = 'Stockholm';
  publicUser.linkedAccounts.github = 'public-user';
  publicUser.preferences.profilePublic = true;
  publicUser.preferences.searchable = true;
  publicUser.preferences.publicProfile.linkedAccounts = true;
  await publicUser.save();

  const privateUser = await createVerifiedUser({
    email: 'private.user@example.com',
    username: 'private.user',
    displayName: 'Private User',
  });
  privateUser.preferences.profilePublic = false;
  privateUser.preferences.searchable = false;
  await privateUser.save();

  const directoryResponse = await request(app)
    .get('/api/auth/public-search')
    .set('Origin', TEST_ORIGIN);

  assert.equal(directoryResponse.status, 200);
  assert.equal(directoryResponse.body.isDirectory, true);
  assert.ok(directoryResponse.body.results.some((entry) => entry.username === 'public.user'));
  assert.ok(!directoryResponse.body.results.some((entry) => entry.username === 'private.user'));

  const profileResponse = await request(app)
    .get('/api/auth/public/public.user')
    .set('Origin', TEST_ORIGIN);

  assert.equal(profileResponse.status, 200);
  assert.equal(profileResponse.body.profile.username, 'public.user');
  assert.equal(profileResponse.body.profile.linkedAccounts.github, 'public-user');

  const hiddenProfileResponse = await request(app)
    .get('/api/auth/public/private.user')
    .set('Origin', TEST_ORIGIN);

  assert.equal(hiddenProfileResponse.status, 404);
});

test('vanguard license route stays optional and returns configured entitlements when enabled', async () => {
  const envKeys = [
    'VANGUARD_API_KEY',
    'VANGUARD_ALLOWED_GUILD_IDS',
    'VANGUARD_LICENSE_AUTHORIZED',
    'VANGUARD_LICENSE_REASON',
    'VANGUARD_ENTITLEMENT_AI',
    'VANGUARD_ENTITLEMENT_ADVANCED_VOTES',
    'VANGUARD_ENTITLEMENT_GUARD_PRESETS',
  ];
  const previousEnv = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]));

  try {
    delete process.env.VANGUARD_API_KEY;

    const disabledResponse = await request(app)
      .get('/api/vanguard/health')
      .set('X-Vanguard-Api-Key', 'unused');

    assert.equal(disabledResponse.status, 503);

    process.env.VANGUARD_API_KEY = 'shared-secret';
    process.env.VANGUARD_ALLOWED_GUILD_IDS = '111111111111111111,222222222222222222';
    process.env.VANGUARD_LICENSE_AUTHORIZED = 'true';
    process.env.VANGUARD_LICENSE_REASON = 'integration enabled';
    process.env.VANGUARD_ENTITLEMENT_AI = 'true';
    process.env.VANGUARD_ENTITLEMENT_ADVANCED_VOTES = 'true';
    process.env.VANGUARD_ENTITLEMENT_GUARD_PRESETS = 'balanced,strict';

    const response = await request(app)
      .post('/api/vanguard/license/verify')
      .set('X-Vanguard-Api-Key', 'shared-secret')
      .set('X-Vanguard-Instance-Id', 'test-instance')
      .send({
        botUserId: '987654321012345678',
        guildCount: 2,
        guildIds: ['111111111111111111', '333333333333333333'],
      });

    assert.equal(response.status, 200);
    assert.equal(response.body.authorized, true);
    assert.equal(response.body.reason, 'integration enabled');
    assert.deepEqual(response.body.allowedGuildIds, ['111111111111111111', '222222222222222222']);
    assert.deepEqual(response.body.entitlements, {
      ai: true,
      advancedVotes: true,
      guardPresets: ['balanced', 'strict'],
    });
    assert.equal(response.body.instanceId, 'test-instance');
  } finally {
    for (const key of envKeys) {
      if (previousEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previousEnv[key];
      }
    }
  }
});

test('vanguard routes resolve, flag, and unflag Discord-linked users without changing auth flows', async () => {
  const envKeys = ['VANGUARD_API_KEY'];
  const previousEnv = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]));

  try {
    process.env.VANGUARD_API_KEY = 'shared-secret';

    const user = await createVerifiedUser({
      email: 'discord.linked@example.com',
      username: 'discord.linked',
      displayName: 'Discord Linked',
    });
    user.oauthIdentities = [
      {
        provider: 'discord',
        providerUserId: '123456789012345678',
        username: 'discord-linked',
        email: 'discord.linked@example.com',
        emailVerified: true,
        profileUrl: 'https://discord.com/users/123456789012345678',
      },
    ];
    user.integrations = {
      vanguard: {
        trusted: true,
      },
    };
    await user.save();

    const resolveResponse = await request(app)
      .post('/api/vanguard/users/resolve')
      .set('X-Vanguard-Api-Key', 'shared-secret')
      .send({ discordUserId: '123456789012345678' });

    assert.equal(resolveResponse.status, 200);
    assert.equal(resolveResponse.body.linked, true);
    assert.equal(resolveResponse.body.user.username, 'discord.linked');
    assert.equal(resolveResponse.body.flags.trusted, true);
    assert.equal(resolveResponse.body.flags.flagged, false);

    const flagResponse = await request(app)
      .post('/api/vanguard/users/flag')
      .set('X-Vanguard-Api-Key', 'shared-secret')
      .set('X-Vanguard-Instance-Id', 'test-instance')
      .send({
        userId: '123456789012345678',
        reason: 'manual moderation review',
      });

    assert.equal(flagResponse.status, 200);
    assert.equal(flagResponse.body.flags.flagged, true);
    assert.equal(flagResponse.body.flags.flagReason, 'manual moderation review');

    const loginResponse = await request(app)
      .post('/api/auth/login')
      .set('Origin', TEST_ORIGIN)
      .set('X-Forwarded-Proto', 'https')
      .send({
        identifier: 'discord.linked',
        password: 'StrongPass1',
      });

    const meResponse = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${loginResponse.body.token}`);

    assert.equal(meResponse.status, 200);
    assert.equal(meResponse.body.user.vanguard.linkedDiscord, true);
    assert.equal(meResponse.body.user.vanguard.trusted, true);
    assert.equal(meResponse.body.user.vanguard.flagged, true);
    assert.equal(meResponse.body.user.vanguard.flagReason, 'manual moderation review');

    const unflagResponse = await request(app)
      .post('/api/vanguard/users/unflag')
      .set('X-Vanguard-Api-Key', 'shared-secret')
      .send({ userId: '123456789012345678' });

    assert.equal(unflagResponse.status, 200);
    assert.equal(unflagResponse.body.flags.flagged, false);

    const refreshedUser = await User.findById(user._id).lean();
    assert.equal(refreshedUser.integrations.vanguard.flagged, false);
    assert.equal(refreshedUser.integrations.vanguard.flagReason, '');
  } finally {
    for (const key of envKeys) {
      if (previousEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previousEnv[key];
      }
    }
  }
});
