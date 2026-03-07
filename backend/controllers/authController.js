const User = require('../models/User');
const jwt = require('jsonwebtoken');

const signToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

const signRefreshToken = (userId) => {
  return jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
};

const buildUserPayload = (user) => ({
  userId: user._id,
  continentalId: user._id,
  email: user.email,
  lastLoginAt: user.lastLoginAt || null,
  lastLoginIp: user.lastLoginIp || null,
  recentLogins: Array.isArray(user.recentLogins) ? user.recentLogins.slice(-5).reverse() : [],
});

const buildCookieOptions = (req) => {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  return {
    httpOnly: true,
    secure: isSecure,
    sameSite: isSecure ? 'None' : 'Lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  };
};

const normalizeEmail = (email) => String(email || '').trim().toLowerCase();

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const isStrongPassword = (password) => typeof password === 'string' && password.length >= 8;

exports.register = async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const { password } = req.body;

  try {
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'Please provide a valid email address.' });
    }
    if (!isStrongPassword(password)) {
      return res.status(400).json({ message: 'Password must be at least 8 characters.' });
    }

    if (await User.findOne({ email })) {
      return res.status(400).json({ message: 'User already exists.' });
    }

    const user = new User({ email, password });
    await user.save();

    const accessToken = signToken(user._id);
    const refreshToken = signRefreshToken(user._id); // same refresh token function as in login

    const cookieOptions = buildCookieOptions(req);

    // Set refresh token as httpOnly cookie
    res.cookie('refreshToken', refreshToken, cookieOptions);

    res.status(201).json({ token: accessToken, ...buildUserPayload(user) });

  } catch (err) {
    res.status(500).json({ message: 'Registration failed.' });
  }
};

exports.login = async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const { password } = req.body;
  try {
    if (!isValidEmail(email) || !password) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const clientIp = req.headers['x-forwarded-for']
      ? String(req.headers['x-forwarded-for']).split(',')[0].trim()
      : req.ip;
    const userAgent = req.headers['user-agent'] || '';
    user.lastLoginAt = new Date();
    user.lastLoginIp = clientIp || '';
    user.recentLogins = Array.isArray(user.recentLogins) ? user.recentLogins : [];
    user.recentLogins.push({ at: user.lastLoginAt, ip: user.lastLoginIp, userAgent });
    if (user.recentLogins.length > 10) {
      user.recentLogins = user.recentLogins.slice(-10);
    }
    await user.save();

    const accessToken = signToken(user._id);
    const refreshToken = signRefreshToken(user._id);

    const cookieOptions = buildCookieOptions(req);

    res.cookie('refreshToken', refreshToken, cookieOptions);

    res.status(200).json({ token: accessToken, ...buildUserPayload(user) });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Login failed.' });
  }
};


exports.logout = (req, res) => {
  // For header-based JWT, there's no cookie—client just deletes token locally
  res.status(200).json({ message: 'Logged out successfully.' });
};

exports.getUserInfo = async (req, res) => {
  try {
    const userId = req.userId;// assuming your auth middleware sets req.user
    const user = await User.findById(userId).select('email');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(buildUserPayload(user));
  } catch (err) {
    res.status(500).json({ message: 'Failed to get user info' });
  }
};

exports.me = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('email lastLoginAt lastLoginIp recentLogins');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(buildUserPayload(user));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to get user info' });
  }
};

// Example refresh token handler
exports.refreshToken = (req, res) => {
  console.log("Refresh Token requested");
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ message: "No refresh token" });

  try {
    const payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const newAccessToken = signToken(payload.userId);  // use your signToken helper
    res.json({ accessToken: newAccessToken, userId: payload.userId, continentalId: payload.userId });
  } catch (err) {
    return res.status(403).json({ message: "Invalid refresh token" });
  }
};

exports.updateEmail = async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  if (!isValidEmail(email)) {
    return res.status(400).json({ message: 'Please provide a valid email address.' });
  }

  try {
    const existing = await User.findOne({ email });
    if (existing && String(existing._id) !== String(req.user.id)) {
      return res.status(409).json({ message: 'Email is already in use.' });
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { email },
      { new: true, runValidators: true }
    ).select('email lastLoginAt lastLoginIp recentLogins');

    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ message: 'Email updated.', ...buildUserPayload(user) });
  } catch (err) {
    console.error('Update email error:', err);
    return res.status(500).json({ message: 'Failed to update email.' });
  }
};

exports.updatePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};

  if (!isStrongPassword(newPassword)) {
    return res.status(400).json({ message: 'New password must be at least 8 characters.' });
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const matches = await user.comparePassword(currentPassword || '');
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    user.password = newPassword;
    await user.save();

    return res.json({ message: 'Password updated.' });
  } catch (err) {
    console.error('Update password error:', err);
    return res.status(500).json({ message: 'Failed to update password.' });
  }
};

exports.deleteAccount = async (req, res) => {
  const { currentPassword, confirmText } = req.body || {};
  if (confirmText !== 'DELETE') {
    return res.status(400).json({ message: 'Type DELETE to confirm account removal.' });
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const matches = await user.comparePassword(currentPassword || '');
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    await User.deleteOne({ _id: req.user.id });
    return res.json({ message: 'Account deleted.' });
  } catch (err) {
    console.error('Delete account error:', err);
    return res.status(500).json({ message: 'Failed to delete account.' });
  }
};
