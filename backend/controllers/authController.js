const jwt = require('jsonwebtoken');
const User = require('../models/User');

const ACCESS_TOKEN_TTL = process.env.JWT_EXPIRES_IN || '1h';
const REFRESH_TOKEN_TTL = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';
const MAX_RECENT_LOGINS = 20;

const toObjectIdString = (value) => String(value || '');

const normalizeEmail = (email) => String(email || '').trim().toLowerCase();
const sanitizeText = (value, maxLength = 120) => String(value || '').trim().slice(0, maxLength);

const sanitizeDisplayName = (displayName, email = '') => {
  const cleaned = sanitizeText(displayName, 60);
  if (cleaned.length >= 2) return cleaned;

  const fallback = sanitizeText(String(email).split('@')[0], 60);
  return fallback || 'User';
};

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const isStrongPassword = (password) => {
  if (typeof password !== 'string') return false;
  if (password.length < 8) return false;

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);

  return hasUppercase && hasLowercase && hasNumber;
};

const parseClientIp = (req) => {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return sanitizeText(String(forwarded).split(',')[0], 80);
  }
  return sanitizeText(req.ip || 'unknown', 80);
};

const buildCookieOptions = (req) => {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';

  return {
    httpOnly: true,
    secure: isSecure,
    sameSite: isSecure ? 'None' : 'Lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  };
};

const clearRefreshCookie = (res, req) => {
  const cookieOptions = buildCookieOptions(req);
  res.clearCookie('refreshToken', {
    httpOnly: cookieOptions.httpOnly,
    secure: cookieOptions.secure,
    sameSite: cookieOptions.sameSite,
    path: cookieOptions.path,
  });
};

const signToken = (user) =>
  jwt.sign(
    {
      userId: toObjectIdString(user._id),
      tokenVersion: user.refreshTokenVersion,
    },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL }
  );

const signRefreshToken = (user) =>
  jwt.sign(
    {
      userId: toObjectIdString(user._id),
      tokenVersion: user.refreshTokenVersion,
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: REFRESH_TOKEN_TTL }
  );

const buildUserPayload = (user) => ({
  userId: toObjectIdString(user._id),
  continentalId: toObjectIdString(user._id),
  email: user.email,
  displayName: user.displayName || 'User',
  isVerified: Boolean(user.isVerified),
  createdAt: user.createdAt || null,
  updatedAt: user.updatedAt || null,
  lastLoginAt: user.lastLoginAt || null,
  lastLoginIp: user.lastLoginIp || null,
  recentLogins: Array.isArray(user.recentLogins) ? user.recentLogins.slice(-10).reverse() : [],
  linkedAccounts: {
    google: sanitizeText(user.linkedAccounts?.google || '', 120),
    facebook: sanitizeText(user.linkedAccounts?.facebook || '', 120),
    github: sanitizeText(user.linkedAccounts?.github || '', 120),
    twitter: sanitizeText(user.linkedAccounts?.twitter || '', 120),
  },
  preferences: {
    profilePublic: Boolean(user.preferences?.profilePublic),
    searchable: Boolean(user.preferences?.searchable),
    notifications: {
      email: Boolean(user.preferences?.notifications?.email),
      sms: Boolean(user.preferences?.notifications?.sms),
      push: Boolean(user.preferences?.notifications?.push),
    },
  },
  security: {
    twoFactorEnabled: Boolean(user.security?.twoFactorEnabled),
    passwordChangedAt: user.security?.passwordChangedAt || null,
  },
});

const sendUserResponse = (res, status, message, user, extra = {}) => {
  const payload = buildUserPayload(user);

  return res.status(status).json({
    message,
    ...extra,
    ...payload,
    user: payload,
  });
};

const getUserById = (id) =>
  User.findById(id).select(
    'email displayName isVerified lastLoginAt lastLoginIp recentLogins linkedAccounts preferences security createdAt updatedAt refreshTokenVersion password'
  );

const normalizeLinkedAccounts = (input = {}) => ({
  google: sanitizeText(input.google, 120),
  facebook: sanitizeText(input.facebook, 120),
  github: sanitizeText(input.github, 120),
  twitter: sanitizeText(input.twitter, 120),
});

const normalizePreferences = (input = {}) => ({
  profilePublic: Boolean(input.profilePublic),
  searchable: Boolean(input.searchable),
  notifications: {
    email: Boolean(input.notifications?.email),
    sms: Boolean(input.notifications?.sms),
    push: Boolean(input.notifications?.push),
  },
});

const appendRecentLogin = (user, req) => {
  const entry = {
    at: new Date(),
    ip: parseClientIp(req),
    userAgent: sanitizeText(req.headers['user-agent'] || 'Unknown', 300),
  };

  user.lastLoginAt = entry.at;
  user.lastLoginIp = entry.ip;

  const list = Array.isArray(user.recentLogins) ? user.recentLogins : [];
  list.push(entry);

  user.recentLogins = list.slice(-MAX_RECENT_LOGINS);
};

const invalidateRefreshSessions = async (user) => {
  user.refreshTokenVersion += 1;
  await user.save();
};

const refreshSessionFromCookie = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return null;

  let payload;
  try {
    payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch {
    clearRefreshCookie(res, req);
    return null;
  }

  const user = await getUserById(payload.userId);
  if (!user) {
    clearRefreshCookie(res, req);
    return null;
  }

  if (user.refreshTokenVersion !== payload.tokenVersion) {
    clearRefreshCookie(res, req);
    return null;
  }

  return user;
};

exports.register = async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;
  const displayName = sanitizeDisplayName(req.body?.displayName, email);

  try {
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'Please provide a valid email address.' });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        message: 'Password must be at least 8 characters and include uppercase, lowercase, and a number.',
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'A user with that email already exists.' });
    }

    const user = new User({
      email,
      password,
      displayName,
    });

    appendRecentLogin(user, req);
    await user.save();

    const accessToken = signToken(user);
    const refreshToken = signRefreshToken(user);
    res.cookie('refreshToken', refreshToken, buildCookieOptions(req));

    return sendUserResponse(res, 201, 'Registration successful.', user, {
      token: accessToken,
      accessToken,
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ message: 'Registration failed.' });
  }
};

exports.login = async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;

  try {
    if (!isValidEmail(email) || typeof password !== 'string') {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    appendRecentLogin(user, req);
    await user.save();

    const accessToken = signToken(user);
    const refreshToken = signRefreshToken(user);

    res.cookie('refreshToken', refreshToken, buildCookieOptions(req));

    return sendUserResponse(res, 200, 'Login successful.', user, {
      token: accessToken,
      accessToken,
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Login failed.' });
  }
};

exports.logout = async (req, res) => {
  try {
    const user = await refreshSessionFromCookie(req, res);
    if (user) {
      await invalidateRefreshSessions(user);
    }

    clearRefreshCookie(res, req);
    return res.status(200).json({ message: 'Logged out successfully.' });
  } catch (err) {
    console.error('Logout error:', err);
    clearRefreshCookie(res, req);
    return res.status(200).json({ message: 'Logged out.' });
  }
};

exports.me = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    return sendUserResponse(res, 200, 'User loaded.', user);
  } catch (err) {
    console.error('Fetch me error:', err);
    return res.status(500).json({ message: 'Failed to fetch user profile.' });
  }
};

exports.refreshToken = async (req, res) => {
  try {
    const user = await refreshSessionFromCookie(req, res);
    if (!user) {
      return res.status(401).json({ message: 'No valid refresh session.' });
    }

    const newAccessToken = signToken(user);
    const rotatedRefreshToken = signRefreshToken(user);
    res.cookie('refreshToken', rotatedRefreshToken, buildCookieOptions(req));

    return res.json({
      message: 'Session refreshed.',
      token: newAccessToken,
      accessToken: newAccessToken,
      userId: toObjectIdString(user._id),
      continentalId: toObjectIdString(user._id),
    });
  } catch (err) {
    console.error('Refresh token error:', err);
    clearRefreshCookie(res, req);
    return res.status(403).json({ message: 'Invalid refresh session.' });
  }
};

exports.updateProfile = async (req, res) => {
  const displayName = sanitizeText(req.body?.displayName, 60);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (displayName.length < 2) {
      return res.status(400).json({ message: 'Display name must be at least 2 characters.' });
    }

    user.displayName = displayName;
    await user.save();

    return sendUserResponse(res, 200, 'Profile updated.', user);
  } catch (err) {
    console.error('Update profile error:', err);
    return res.status(500).json({ message: 'Failed to update profile.' });
  }
};

exports.updateEmail = async (req, res) => {
  const email = normalizeEmail(req.body?.email);

  if (!isValidEmail(email)) {
    return res.status(400).json({ message: 'Please provide a valid email address.' });
  }

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const existing = await User.findOne({ email }).select('_id');
    if (existing && toObjectIdString(existing._id) !== toObjectIdString(user._id)) {
      return res.status(409).json({ message: 'Email is already in use.' });
    }

    user.email = email;
    await user.save();

    return sendUserResponse(res, 200, 'Email updated.', user);
  } catch (err) {
    console.error('Update email error:', err);
    return res.status(500).json({ message: 'Failed to update email.' });
  }
};

exports.getPreferences = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    return res.json({
      message: 'Preferences loaded.',
      preferences: buildUserPayload(user).preferences,
    });
  } catch (err) {
    console.error('Get preferences error:', err);
    return res.status(500).json({ message: 'Failed to load preferences.' });
  }
};

exports.updatePreferences = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const current = buildUserPayload(user).preferences;
    const incoming = req.body || {};

    user.preferences = normalizePreferences({
      profilePublic:
        typeof incoming.profilePublic === 'boolean' ? incoming.profilePublic : current.profilePublic,
      searchable: typeof incoming.searchable === 'boolean' ? incoming.searchable : current.searchable,
      notifications: {
        email:
          typeof incoming.notifications?.email === 'boolean'
            ? incoming.notifications.email
            : current.notifications.email,
        sms:
          typeof incoming.notifications?.sms === 'boolean'
            ? incoming.notifications.sms
            : current.notifications.sms,
        push:
          typeof incoming.notifications?.push === 'boolean'
            ? incoming.notifications.push
            : current.notifications.push,
      },
    });

    await user.save();

    return sendUserResponse(res, 200, 'Preferences updated.', user);
  } catch (err) {
    console.error('Update preferences error:', err);
    return res.status(500).json({ message: 'Failed to update preferences.' });
  }
};

exports.getLinkedAccounts = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    return res.json({
      message: 'Linked accounts loaded.',
      linkedAccounts: buildUserPayload(user).linkedAccounts,
    });
  } catch (err) {
    console.error('Get linked accounts error:', err);
    return res.status(500).json({ message: 'Failed to load linked accounts.' });
  }
};

exports.updateLinkedAccounts = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    user.linkedAccounts = normalizeLinkedAccounts(req.body || {});
    await user.save();

    return sendUserResponse(res, 200, 'Linked accounts updated.', user);
  } catch (err) {
    console.error('Update linked accounts error:', err);
    return res.status(500).json({ message: 'Failed to update linked accounts.' });
  }
};

exports.getActivity = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const payload = buildUserPayload(user);

    return res.json({
      message: 'Activity loaded.',
      recentLogins: payload.recentLogins,
      lastLoginAt: payload.lastLoginAt,
      lastLoginIp: payload.lastLoginIp,
    });
  } catch (err) {
    console.error('Get activity error:', err);
    return res.status(500).json({ message: 'Failed to load activity.' });
  }
};

exports.getSecurity = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const payload = buildUserPayload(user);

    return res.json({
      message: 'Security settings loaded.',
      security: payload.security,
    });
  } catch (err) {
    console.error('Get security error:', err);
    return res.status(500).json({ message: 'Failed to load security settings.' });
  }
};

exports.updateSecurity = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (typeof req.body?.twoFactorEnabled === 'boolean') {
      user.security.twoFactorEnabled = req.body.twoFactorEnabled;
    }

    await user.save();

    return sendUserResponse(res, 200, 'Security settings updated.', user);
  } catch (err) {
    console.error('Update security error:', err);
    return res.status(500).json({ message: 'Failed to update security settings.' });
  }
};

exports.updatePassword = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const newPassword = req.body?.newPassword || '';

  if (!isStrongPassword(newPassword)) {
    return res.status(400).json({
      message: 'New password must be at least 8 characters and include uppercase, lowercase, and a number.',
    });
  }

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    user.password = newPassword;
    user.refreshTokenVersion += 1;
    await user.save();

    clearRefreshCookie(res, req);

    return res.json({
      message: 'Password updated. Please log in again.',
      forceRelogin: true,
    });
  } catch (err) {
    console.error('Update password error:', err);
    return res.status(500).json({ message: 'Failed to update password.' });
  }
};

exports.deleteAccount = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const confirmText = sanitizeText(req.body?.confirmText || '', 20);

  if (confirmText !== 'DELETE') {
    return res.status(400).json({ message: 'Type DELETE to confirm account removal.' });
  }

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    await User.deleteOne({ _id: req.user.id });
    clearRefreshCookie(res, req);

    return res.json({ message: 'Account deleted permanently.' });
  } catch (err) {
    console.error('Delete account error:', err);
    return res.status(500).json({ message: 'Failed to delete account.' });
  }
};
