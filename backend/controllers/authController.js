const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const ACCESS_TOKEN_TTL = process.env.JWT_EXPIRES_IN || '1h';
const REFRESH_TOKEN_TTL = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';

const MAX_RECENT_LOGINS = 20;
const MAX_ACTIVE_SESSIONS = 12;
const LOGIN_RATE_WINDOW_MS = Number(process.env.LOGIN_RATE_WINDOW_MS) || 10 * 60 * 1000;
const LOGIN_RATE_MAX_ATTEMPTS = Number(process.env.LOGIN_RATE_MAX_ATTEMPTS) || 8;
const LOGIN_BLOCK_MS = Number(process.env.LOGIN_BLOCK_MS) || 15 * 60 * 1000;

const LINKED_PROVIDERS = [
  'google',
  'facebook',
  'github',
  'twitter',
  'linkedin',
  'discord',
  'apple',
  'microsoft',
];

const ALLOWED_THEMES = new Set(['system', 'dawn', 'night', 'ocean']);
const ALLOWED_DENSITIES = new Set(['comfortable', 'compact', 'spacious']);

const DEFAULT_NOTIFICATIONS = {
  email: true,
  sms: false,
  push: true,
  weeklyDigest: true,
  security: true,
};

const DEFAULT_APPEARANCE = {
  theme: 'system',
  compactMode: false,
  reducedMotion: false,
  highContrast: false,
  dashboardDensity: 'comfortable',
};

const LOGIN_FAILURE_STORE = new Map();

const cleanupLoginFailureStore = () => {
  const now = Date.now();
  for (const [key, value] of LOGIN_FAILURE_STORE.entries()) {
    const expiredWindow = now - value.windowStart > LOGIN_RATE_WINDOW_MS;
    const expiredBlock = !value.blockedUntil || value.blockedUntil <= now;
    if (expiredWindow && expiredBlock) {
      LOGIN_FAILURE_STORE.delete(key);
    }
  }
};

const loginFailureCleanupInterval = setInterval(
  cleanupLoginFailureStore,
  Math.max(60_000, Math.floor(LOGIN_RATE_WINDOW_MS / 2))
);
if (typeof loginFailureCleanupInterval.unref === 'function') {
  loginFailureCleanupInterval.unref();
}

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj || {}, key);

const toObjectIdString = (value) => String(value || '');
const normalizeEmail = (email) => String(email || '').trim().toLowerCase();
const sanitizeText = (value, maxLength = 120) => String(value || '').trim().slice(0, maxLength);

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const sanitizeDisplayName = (displayName, email = '') => {
  const cleaned = sanitizeText(displayName, 60);
  if (cleaned.length >= 2) return cleaned;

  const fallback = sanitizeText(String(email).split('@')[0], 60);
  return fallback || 'User';
};

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

const parseUserAgent = (req) => sanitizeText(req.headers['user-agent'] || 'Unknown browser/device', 300);

const buildSessionLabel = (requestedLabel, userAgent = '') => {
  const explicit = sanitizeText(requestedLabel, 60);
  if (explicit) return explicit;

  const ua = sanitizeText(userAgent, 260).toLowerCase();
  if (!ua) return 'Browser session';

  if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) return 'iOS browser';
  if (ua.includes('android')) return 'Android browser';
  if (ua.includes('firefox')) return 'Firefox';
  if (ua.includes('edg/')) return 'Edge';
  if (ua.includes('chrome')) return 'Chrome';
  if (ua.includes('safari')) return 'Safari';
  return 'Browser session';
};

const sanitizeWebsite = (value, fallback = '') => {
  const raw = sanitizeText(value, 240);
  if (!raw) return '';

  const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;

  try {
    const parsed = new URL(withProtocol);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return fallback;
    }
    return parsed.toString();
  } catch {
    return fallback;
  }
};

const sanitizeLanguage = (value, fallback = 'en') => {
  const raw = sanitizeText(value, 32).replace('_', '-');
  if (!raw) return fallback;
  if (/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$/.test(raw)) return raw;
  return fallback;
};

const sanitizeTimezone = (value, fallback = 'UTC') => {
  const candidate = sanitizeText(value, 80);
  if (!candidate) return fallback;

  try {
    Intl.DateTimeFormat(undefined, { timeZone: candidate });
    return candidate;
  } catch {
    return fallback;
  }
};

const normalizeProfile = (incoming = {}, current = {}) => {
  const currentProfile = current || {};

  return {
    bio: hasOwn(incoming, 'bio') ? sanitizeText(incoming.bio, 320) : sanitizeText(currentProfile.bio, 320),
    location: hasOwn(incoming, 'location')
      ? sanitizeText(incoming.location, 120)
      : sanitizeText(currentProfile.location, 120),
    website: hasOwn(incoming, 'website')
      ? sanitizeWebsite(incoming.website, sanitizeText(currentProfile.website, 240))
      : sanitizeWebsite(currentProfile.website, ''),
    timezone: hasOwn(incoming, 'timezone')
      ? sanitizeTimezone(incoming.timezone, sanitizeTimezone(currentProfile.timezone, 'UTC'))
      : sanitizeTimezone(currentProfile.timezone, 'UTC'),
    language: hasOwn(incoming, 'language')
      ? sanitizeLanguage(incoming.language, sanitizeLanguage(currentProfile.language, 'en'))
      : sanitizeLanguage(currentProfile.language, 'en'),
  };
};

const normalizeLinkedAccounts = (input = {}, current = {}) => {
  const next = {};

  for (const provider of LINKED_PROVIDERS) {
    if (hasOwn(input, provider)) {
      next[provider] = sanitizeText(input[provider], 120);
      continue;
    }
    next[provider] = sanitizeText(current?.[provider], 120);
  }

  return next;
};

const normalizeTheme = (value, fallback = 'system') => {
  const candidate = sanitizeText(value, 20).toLowerCase();
  if (ALLOWED_THEMES.has(candidate)) return candidate;
  return fallback;
};

const normalizeDensity = (value, fallback = 'comfortable') => {
  const candidate = sanitizeText(value, 20).toLowerCase();
  if (ALLOWED_DENSITIES.has(candidate)) return candidate;
  return fallback;
};

const normalizeAppearance = (incoming = {}, current = {}) => {
  const source = current || {};
  const next = {
    theme: hasOwn(incoming, 'theme')
      ? normalizeTheme(incoming.theme, normalizeTheme(source.theme || DEFAULT_APPEARANCE.theme))
      : normalizeTheme(source.theme || DEFAULT_APPEARANCE.theme),
    compactMode: hasOwn(incoming, 'compactMode')
      ? Boolean(incoming.compactMode)
      : Boolean(hasOwn(source, 'compactMode') ? source.compactMode : DEFAULT_APPEARANCE.compactMode),
    reducedMotion: hasOwn(incoming, 'reducedMotion')
      ? Boolean(incoming.reducedMotion)
      : Boolean(hasOwn(source, 'reducedMotion') ? source.reducedMotion : DEFAULT_APPEARANCE.reducedMotion),
    highContrast: hasOwn(incoming, 'highContrast')
      ? Boolean(incoming.highContrast)
      : Boolean(hasOwn(source, 'highContrast') ? source.highContrast : DEFAULT_APPEARANCE.highContrast),
    dashboardDensity: hasOwn(incoming, 'dashboardDensity')
      ? normalizeDensity(
          incoming.dashboardDensity,
          normalizeDensity(source.dashboardDensity || DEFAULT_APPEARANCE.dashboardDensity)
        )
      : normalizeDensity(source.dashboardDensity || DEFAULT_APPEARANCE.dashboardDensity),
  };

  return next;
};

const normalizePreferences = (incoming = {}, current = {}) => {
  const source = current || {};
  const sourceNotifications = source.notifications || DEFAULT_NOTIFICATIONS;
  const incomingNotifications = incoming.notifications || {};

  return {
    profilePublic: hasOwn(incoming, 'profilePublic')
      ? Boolean(incoming.profilePublic)
      : Boolean(hasOwn(source, 'profilePublic') ? source.profilePublic : true),
    searchable: hasOwn(incoming, 'searchable')
      ? Boolean(incoming.searchable)
      : Boolean(hasOwn(source, 'searchable') ? source.searchable : true),
    notifications: {
      email: hasOwn(incomingNotifications, 'email')
        ? Boolean(incomingNotifications.email)
        : Boolean(hasOwn(sourceNotifications, 'email') ? sourceNotifications.email : DEFAULT_NOTIFICATIONS.email),
      sms: hasOwn(incomingNotifications, 'sms')
        ? Boolean(incomingNotifications.sms)
        : Boolean(hasOwn(sourceNotifications, 'sms') ? sourceNotifications.sms : DEFAULT_NOTIFICATIONS.sms),
      push: hasOwn(incomingNotifications, 'push')
        ? Boolean(incomingNotifications.push)
        : Boolean(hasOwn(sourceNotifications, 'push') ? sourceNotifications.push : DEFAULT_NOTIFICATIONS.push),
      weeklyDigest: hasOwn(incomingNotifications, 'weeklyDigest')
        ? Boolean(incomingNotifications.weeklyDigest)
        : Boolean(
            hasOwn(sourceNotifications, 'weeklyDigest')
              ? sourceNotifications.weeklyDigest
              : DEFAULT_NOTIFICATIONS.weeklyDigest
          ),
      security: hasOwn(incomingNotifications, 'security')
        ? Boolean(incomingNotifications.security)
        : Boolean(
            hasOwn(sourceNotifications, 'security')
              ? sourceNotifications.security
              : DEFAULT_NOTIFICATIONS.security
          ),
    },
    appearance: normalizeAppearance(incoming.appearance || {}, source.appearance || DEFAULT_APPEARANCE),
  };
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

const signToken = (user, sid) =>
  jwt.sign(
    {
      userId: toObjectIdString(user._id),
      tokenVersion: user.refreshTokenVersion,
      sid: sanitizeText(sid, 120) || undefined,
    },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL }
  );

const signRefreshToken = (user, sid) =>
  jwt.sign(
    {
      userId: toObjectIdString(user._id),
      tokenVersion: user.refreshTokenVersion,
      sid: sanitizeText(sid, 120) || undefined,
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: REFRESH_TOKEN_TTL }
  );

const appendRecentLogin = (user, req) => {
  const entry = {
    at: new Date(),
    ip: parseClientIp(req),
    userAgent: parseUserAgent(req),
  };

  user.lastLoginAt = entry.at;
  user.lastLoginIp = entry.ip;

  const list = Array.isArray(user.recentLogins) ? [...user.recentLogins] : [];
  list.push(entry);

  user.recentLogins = list.slice(-MAX_RECENT_LOGINS);
};

const upsertRefreshSession = (user, req, sid = '', requestedLabel = '') => {
  const sessions = Array.isArray(user.refreshSessions) ? [...user.refreshSessions] : [];
  const sessionId = sanitizeText(sid, 120) || crypto.randomUUID();
  const now = new Date();
  const ip = parseClientIp(req);
  const userAgent = parseUserAgent(req);
  const label = buildSessionLabel(requestedLabel, userAgent);

  const existingIndex = sessions.findIndex(
    (session) => sanitizeText(session.sid, 120) === sessionId
  );

  if (existingIndex >= 0) {
    sessions[existingIndex] = {
      ...sessions[existingIndex],
      sid: sessionId,
      label: label || sessions[existingIndex].label || 'Browser session',
      createdAt: sessions[existingIndex].createdAt || now,
      lastUsedAt: now,
      ip,
      userAgent,
    };
  } else {
    sessions.push({
      sid: sessionId,
      label,
      createdAt: now,
      lastUsedAt: now,
      ip,
      userAgent,
    });
  }

  sessions.sort((a, b) => {
    const aTime = new Date(a.lastUsedAt || a.createdAt || 0).getTime();
    const bTime = new Date(b.lastUsedAt || b.createdAt || 0).getTime();
    return aTime - bTime;
  });

  while (sessions.length > MAX_ACTIVE_SESSIONS) {
    sessions.shift();
  }

  user.refreshSessions = sessions;
  return sessionId;
};

const removeRefreshSession = (user, sid) => {
  const sessionId = sanitizeText(sid, 120);
  if (!sessionId) return false;

  const sessions = Array.isArray(user.refreshSessions) ? user.refreshSessions : [];
  const next = sessions.filter((session) => sanitizeText(session.sid, 120) !== sessionId);

  if (next.length === sessions.length) {
    return false;
  }

  user.refreshSessions = next;
  return true;
};

const revokeAllSessions = (user, currentSid, exceptCurrent = false) => {
  const sessions = Array.isArray(user.refreshSessions) ? user.refreshSessions : [];

  if (exceptCurrent && currentSid) {
    user.refreshSessions = sessions.filter(
      (session) => sanitizeText(session.sid, 120) === sanitizeText(currentSid, 120)
    );
    return;
  }

  user.refreshSessions = [];
};

const serializeSession = (session, currentSid = '') => {
  const sid = sanitizeText(session?.sid, 120);
  return {
    sid,
    label: sanitizeText(session?.label, 60) || 'Browser session',
    createdAt: session?.createdAt || null,
    lastUsedAt: session?.lastUsedAt || null,
    ip: sanitizeText(session?.ip, 80),
    userAgent: sanitizeText(session?.userAgent, 300),
    current: Boolean(sid && sid === sanitizeText(currentSid, 120)),
  };
};

const profileCompletion = (user) => {
  const fields = [
    sanitizeText(user.displayName, 60),
    sanitizeText(user.email, 120),
    sanitizeText(user.profile?.bio, 320),
    sanitizeText(user.profile?.location, 120),
    sanitizeText(user.profile?.website, 240),
    sanitizeText(user.profile?.timezone, 80),
    sanitizeText(user.profile?.language, 32),
  ];

  const filled = fields.filter(Boolean).length;
  return Math.round((filled / fields.length) * 100);
};

const buildUserPayload = (user) => {
  const linkedAccounts = {};
  for (const provider of LINKED_PROVIDERS) {
    linkedAccounts[provider] = sanitizeText(user.linkedAccounts?.[provider] || '', 120);
  }

  return {
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
    profile: {
      bio: sanitizeText(user.profile?.bio, 320),
      location: sanitizeText(user.profile?.location, 120),
      website: sanitizeText(user.profile?.website, 240),
      timezone: sanitizeTimezone(user.profile?.timezone, 'UTC'),
      language: sanitizeLanguage(user.profile?.language, 'en'),
      completion: profileCompletion(user),
    },
    linkedAccounts,
    preferences: {
      profilePublic: Boolean(
        hasOwn(user.preferences || {}, 'profilePublic') ? user.preferences?.profilePublic : true
      ),
      searchable: Boolean(hasOwn(user.preferences || {}, 'searchable') ? user.preferences?.searchable : true),
      notifications: {
        email: Boolean(
          hasOwn(user.preferences?.notifications || {}, 'email')
            ? user.preferences?.notifications?.email
            : DEFAULT_NOTIFICATIONS.email
        ),
        sms: Boolean(
          hasOwn(user.preferences?.notifications || {}, 'sms')
            ? user.preferences?.notifications?.sms
            : DEFAULT_NOTIFICATIONS.sms
        ),
        push: Boolean(
          hasOwn(user.preferences?.notifications || {}, 'push')
            ? user.preferences?.notifications?.push
            : DEFAULT_NOTIFICATIONS.push
        ),
        weeklyDigest: Boolean(
          hasOwn(user.preferences?.notifications || {}, 'weeklyDigest')
            ? user.preferences?.notifications?.weeklyDigest
            : DEFAULT_NOTIFICATIONS.weeklyDigest
        ),
        security: Boolean(
          hasOwn(user.preferences?.notifications || {}, 'security')
            ? user.preferences?.notifications?.security
            : DEFAULT_NOTIFICATIONS.security
        ),
      },
      appearance: {
        theme: normalizeTheme(user.preferences?.appearance?.theme || DEFAULT_APPEARANCE.theme),
        compactMode: Boolean(
          hasOwn(user.preferences?.appearance || {}, 'compactMode')
            ? user.preferences?.appearance?.compactMode
            : DEFAULT_APPEARANCE.compactMode
        ),
        reducedMotion: Boolean(
          hasOwn(user.preferences?.appearance || {}, 'reducedMotion')
            ? user.preferences?.appearance?.reducedMotion
            : DEFAULT_APPEARANCE.reducedMotion
        ),
        highContrast: Boolean(
          hasOwn(user.preferences?.appearance || {}, 'highContrast')
            ? user.preferences?.appearance?.highContrast
            : DEFAULT_APPEARANCE.highContrast
        ),
        dashboardDensity: normalizeDensity(
          user.preferences?.appearance?.dashboardDensity || DEFAULT_APPEARANCE.dashboardDensity
        ),
      },
    },
    security: {
      twoFactorEnabled: Boolean(user.security?.twoFactorEnabled),
      loginAlerts: Boolean(hasOwn(user.security || {}, 'loginAlerts') ? user.security?.loginAlerts : true),
      passwordChangedAt: user.security?.passwordChangedAt || null,
      activeSessions: Array.isArray(user.refreshSessions) ? user.refreshSessions.length : 0,
    },
  };
};

const sendUserResponse = (res, status, message, user, extra = {}) => {
  const payload = buildUserPayload(user);

  return res.status(status).json({
    message,
    ...extra,
    ...payload,
    user: payload,
  });
};

const buildActivitySummary = (recentLogins = []) => {
  const now = Date.now();
  const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;
  const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;

  let last7Days = 0;
  let last30Days = 0;
  const uniqueIps = new Set();
  const byDay = new Map();

  for (const entry of recentLogins) {
    const timestamp = new Date(entry?.at || '').getTime();
    if (Number.isNaN(timestamp)) continue;

    if (timestamp >= sevenDaysAgo) last7Days += 1;
    if (timestamp >= thirtyDaysAgo) last30Days += 1;

    const ip = sanitizeText(entry?.ip, 80);
    if (ip) uniqueIps.add(ip);

    const day = new Date(timestamp).toISOString().slice(0, 10);
    byDay.set(day, (byDay.get(day) || 0) + 1);
  }

  const recentDays = Array.from(byDay.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .slice(-7)
    .map(([day, count]) => ({ day, count }));

  return {
    last7Days,
    last30Days,
    uniqueIps: uniqueIps.size,
    recentDays,
  };
};

const getUserById = (id) =>
  User.findById(id).select(
    'email displayName isVerified verificationToken verificationTokenExpires lastLoginAt lastLoginIp recentLogins profile linkedAccounts preferences security refreshTokenVersion refreshSessions createdAt updatedAt password'
  );

const loginRateKey = (email, req) => `${normalizeEmail(email)}|${parseClientIp(req)}`;

const getLoginThrottleState = (key) => {
  const now = Date.now();
  const entry = LOGIN_FAILURE_STORE.get(key);

  if (!entry) {
    return { blocked: false, retryAfterSec: 0 };
  }

  if (entry.blockedUntil && entry.blockedUntil > now) {
    return {
      blocked: true,
      retryAfterSec: Math.max(1, Math.ceil((entry.blockedUntil - now) / 1000)),
    };
  }

  if (now - entry.windowStart > LOGIN_RATE_WINDOW_MS) {
    LOGIN_FAILURE_STORE.delete(key);
  }

  return { blocked: false, retryAfterSec: 0 };
};

const registerLoginFailure = (key) => {
  const now = Date.now();
  const current = LOGIN_FAILURE_STORE.get(key);

  if (!current || now - current.windowStart > LOGIN_RATE_WINDOW_MS) {
    LOGIN_FAILURE_STORE.set(key, {
      windowStart: now,
      count: 1,
      blockedUntil: 0,
    });
    return;
  }

  current.count += 1;

  if (current.count >= LOGIN_RATE_MAX_ATTEMPTS) {
    current.blockedUntil = now + LOGIN_BLOCK_MS;
  }
};

const clearLoginFailures = (key) => {
  LOGIN_FAILURE_STORE.delete(key);
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

  const sidFromToken = sanitizeText(payload.sid, 120);

  if (sidFromToken) {
    const hasSession = Array.isArray(user.refreshSessions)
      ? user.refreshSessions.some((session) => sanitizeText(session.sid, 120) === sidFromToken)
      : false;

    if (!hasSession) {
      clearRefreshCookie(res, req);
      return null;
    }

    const touchedSid = upsertRefreshSession(user, req, sidFromToken);
    return { user, sid: touchedSid };
  }

  // Legacy refresh token fallback: issue a tracked session immediately.
  const migratedSid = upsertRefreshSession(user, req, '');
  return { user, sid: migratedSid };
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
        message:
          'Password must be at least 8 characters and include uppercase, lowercase, and a number.',
      });
    }

    const existingUser = await User.findOne({ email }).select('_id');
    if (existingUser) {
      return res.status(409).json({ message: 'A user with that email already exists.' });
    }

    const user = new User({
      email,
      password,
      displayName,
      profile: normalizeProfile(req.body || {}, {}),
      preferences: normalizePreferences(req.body?.preferences || {}, {}),
    });

    appendRecentLogin(user, req);
    const sid = upsertRefreshSession(user, req, '', req.body?.deviceLabel);
    await user.save();

    const accessToken = signToken(user, sid);
    const refreshToken = signRefreshToken(user, sid);
    res.cookie('refreshToken', refreshToken, buildCookieOptions(req));

    return sendUserResponse(res, 201, 'Registration successful.', user, {
      token: accessToken,
      accessToken,
      currentSessionId: sid,
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ message: 'Registration failed.' });
  }
};

exports.login = async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;

  const rateKey = loginRateKey(email, req);
  const throttle = getLoginThrottleState(rateKey);
  if (throttle.blocked) {
    return res.status(429).json({
      message: `Too many failed login attempts. Try again in ${throttle.retryAfterSec} seconds.`,
      retryAfterSec: throttle.retryAfterSec,
    });
  }

  try {
    if (!isValidEmail(email) || typeof password !== 'string') {
      registerLoginFailure(rateKey);
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      registerLoginFailure(rateKey);
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      registerLoginFailure(rateKey);
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    clearLoginFailures(rateKey);

    appendRecentLogin(user, req);
    const sid = upsertRefreshSession(user, req, '', req.body?.deviceLabel);
    await user.save();

    const accessToken = signToken(user, sid);
    const refreshToken = signRefreshToken(user, sid);

    res.cookie('refreshToken', refreshToken, buildCookieOptions(req));

    return sendUserResponse(res, 200, 'Login successful.', user, {
      token: accessToken,
      accessToken,
      currentSessionId: sid,
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Login failed.' });
  }
};

exports.logout = async (req, res) => {
  try {
    const session = await refreshSessionFromCookie(req, res);
    if (session?.user) {
      if (session.sid) {
        removeRefreshSession(session.user, session.sid);
      } else {
        session.user.refreshTokenVersion += 1;
        session.user.refreshSessions = [];
      }
      await session.user.save();
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
    const session = await refreshSessionFromCookie(req, res);
    if (!session?.user) {
      return res.status(401).json({ message: 'No valid refresh session.' });
    }

    await session.user.save();

    const newAccessToken = signToken(session.user, session.sid);
    const rotatedRefreshToken = signRefreshToken(session.user, session.sid);
    res.cookie('refreshToken', rotatedRefreshToken, buildCookieOptions(req));

    return res.json({
      message: 'Session refreshed.',
      token: newAccessToken,
      accessToken: newAccessToken,
      userId: toObjectIdString(session.user._id),
      continentalId: toObjectIdString(session.user._id),
      currentSessionId: session.sid,
    });
  } catch (err) {
    console.error('Refresh token error:', err);
    clearRefreshCookie(res, req);
    return res.status(403).json({ message: 'Invalid refresh session.' });
  }
};

exports.updateProfile = async (req, res) => {
  const incoming = req.body || {};

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (hasOwn(incoming, 'displayName')) {
      const displayName = sanitizeText(incoming.displayName, 60);
      if (displayName.length < 2) {
        return res.status(400).json({ message: 'Display name must be at least 2 characters.' });
      }
      user.displayName = displayName;
    }

    user.profile = normalizeProfile(incoming, user.profile || {});
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

    user.preferences = normalizePreferences(req.body || {}, user.preferences || {});
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

    user.linkedAccounts = normalizeLinkedAccounts(req.body || {}, user.linkedAccounts || {});
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
      summary: buildActivitySummary(Array.isArray(user.recentLogins) ? user.recentLogins : []),
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
      sessionLimit: MAX_ACTIVE_SESSIONS,
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

    if (typeof req.body?.loginAlerts === 'boolean') {
      user.security.loginAlerts = req.body.loginAlerts;
    }

    await user.save();

    return sendUserResponse(res, 200, 'Security settings updated.', user);
  } catch (err) {
    console.error('Update security error:', err);
    return res.status(500).json({ message: 'Failed to update security settings.' });
  }
};

exports.getSessions = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const currentSid = sanitizeText(req.user?.sid, 120);
    const sessions = Array.isArray(user.refreshSessions)
      ? [...user.refreshSessions]
          .map((session) => serializeSession(session, currentSid))
          .sort((a, b) => {
            const aTime = new Date(a.lastUsedAt || a.createdAt || 0).getTime();
            const bTime = new Date(b.lastUsedAt || b.createdAt || 0).getTime();
            return bTime - aTime;
          })
      : [];

    return res.json({
      message: 'Sessions loaded.',
      sessions,
      sessionLimit: MAX_ACTIVE_SESSIONS,
    });
  } catch (err) {
    console.error('Get sessions error:', err);
    return res.status(500).json({ message: 'Failed to load sessions.' });
  }
};

exports.revokeSession = async (req, res) => {
  const targetSid = sanitizeText(req.params?.sessionId, 120);

  if (!targetSid) {
    return res.status(400).json({ message: 'A valid session id is required.' });
  }

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const removed = removeRefreshSession(user, targetSid);
    if (!removed) {
      return res.status(404).json({ message: 'Session not found.' });
    }

    await user.save();

    const currentSid = sanitizeText(req.user?.sid, 120);
    const revokedCurrentSession = targetSid === currentSid;
    if (revokedCurrentSession) {
      clearRefreshCookie(res, req);
    }

    return res.json({
      message: revokedCurrentSession
        ? 'Current session revoked. Please sign in again to refresh your session.'
        : 'Session revoked.',
      revokedCurrentSession,
      forceRelogin: revokedCurrentSession,
    });
  } catch (err) {
    console.error('Revoke session error:', err);
    return res.status(500).json({ message: 'Failed to revoke session.' });
  }
};

exports.revokeAllSessions = async (req, res) => {
  const exceptCurrent = Boolean(req.body?.exceptCurrent);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const currentSid = sanitizeText(req.user?.sid, 120);
    revokeAllSessions(user, currentSid, exceptCurrent);

    if (!exceptCurrent || !currentSid) {
      user.refreshTokenVersion += 1;
      clearRefreshCookie(res, req);
    }

    await user.save();

    return res.json({
      message: exceptCurrent
        ? 'All other sessions were revoked.'
        : 'All sessions were revoked. Please sign in again.',
      forceRelogin: !exceptCurrent || !currentSid,
    });
  } catch (err) {
    console.error('Revoke all sessions error:', err);
    return res.status(500).json({ message: 'Failed to revoke sessions.' });
  }
};

exports.updatePassword = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const newPassword = req.body?.newPassword || '';

  if (!isStrongPassword(newPassword)) {
    return res.status(400).json({
      message:
        'New password must be at least 8 characters and include uppercase, lowercase, and a number.',
    });
  }

  if (newPassword === currentPassword) {
    return res.status(400).json({ message: 'New password must be different from current password.' });
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
    user.refreshSessions = [];
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

exports.exportAccountData = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const payload = buildUserPayload(user);
    const sessions = Array.isArray(user.refreshSessions)
      ? user.refreshSessions.map((session) => serializeSession(session, req.user?.sid))
      : [];

    return res.json({
      message: 'Account export generated.',
      exportedAt: new Date().toISOString(),
      data: {
        account: payload,
        sessions,
        activitySummary: buildActivitySummary(Array.isArray(user.recentLogins) ? user.recentLogins : []),
      },
    });
  } catch (err) {
    console.error('Export account error:', err);
    return res.status(500).json({ message: 'Failed to export account data.' });
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
