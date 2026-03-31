const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const LoginThrottle = require('../models/LoginThrottle');
const User = require('../models/User');
const sendEmail = require('../utils/email');
const { createEmailVerificationToken } = require('../utils/emailVerification');
const {
  USERNAME_VALIDATION_MESSAGE,
  ensureStoredUsername,
  ensureUserIdentityFields,
  getDisplayableUsername,
  isValidUsername,
  normalizeUsername,
} = require('../utils/userIdentity');

const ACCESS_TOKEN_TTL = process.env.JWT_EXPIRES_IN || '1h';
const REFRESH_TOKEN_TTL = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_RECENT_LOGIN_EVENTS = 50;
const RECENT_LOGIN_RESPONSE_LIMIT = 20;
const MAX_ACTIVE_SESSIONS = 12;
const LOGIN_RATE_WINDOW_MS = Number(process.env.LOGIN_RATE_WINDOW_MS) || 10 * 60 * 1000;
const LOGIN_RATE_MAX_ATTEMPTS = Number(process.env.LOGIN_RATE_MAX_ATTEMPTS) || 8;
const LOGIN_BLOCK_MS = Number(process.env.LOGIN_BLOCK_MS) || 15 * 60 * 1000;
const REFRESH_TOKEN_REPLAY_GRACE_MS =
  Number(process.env.REFRESH_TOKEN_REPLAY_GRACE_MS) || 15_000;
const LOGIN_ACTIVITY_RETENTION_DAYS = 45;
const MAX_AUDIT_EVENTS = 120;
const MAX_KNOWN_DEVICES = 24;
const PASSWORD_RESET_TTL_MS = Number(process.env.PASSWORD_RESET_TTL_MS) || 60 * 60 * 1000;
const NEW_DEVICE_SESSION_WINDOW_MS = 15 * 60 * 1000;

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

const DEFAULT_EMAIL_VERIFY_PATH = '/login/verify.html';
const DEFAULT_PASSWORD_RESET_PATH = '/login/reset-password.html';
const EMAIL_VERIFICATION_SUBJECT = 'Verify your Continental ID email';
const PASSWORD_RESET_SUBJECT = 'Reset your Continental ID password';
const AVATAR_DATA_URL_MAX_LENGTH = 350000;
const AVATAR_DATA_URL_PATTERN = /^data:image\/(?:png|jpe?g|gif|webp);base64,[a-z0-9+/=]+$/i;

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj || {}, key);

const toObjectIdString = (value) => String(value || '');
const normalizeEmail = (email) => String(email || '').trim().toLowerCase();
const normalizeLoginIdentifier = (value) => String(value || '').trim().toLowerCase();
const sanitizeText = (value, maxLength = 120) => String(value || '').trim().slice(0, maxLength);
const hashToken = (value) => crypto.createHash('sha256').update(String(value || '')).digest('hex');

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
  return sanitizeText(req.ip || req.socket?.remoteAddress || 'unknown', 80);
};

const parseUserAgent = (req) => sanitizeText(req.headers['user-agent'] || 'Unknown browser/device', 300);

const buildLoginThrottleExpiry = (now = Date.now()) =>
  new Date(now + Math.max(LOGIN_RATE_WINDOW_MS, LOGIN_BLOCK_MS) + 60_000);

const isDuplicateKeyError = (err) => err?.code === 11000;
const getDuplicateFieldName = (err) =>
  Object.keys(err?.keyPattern || err?.keyValue || {}).find(Boolean) || '';
const getDuplicateUserFieldMessage = (err) => {
  const field = getDuplicateFieldName(err);
  if (field === 'username') return 'Username is already in use.';
  if (field === 'email') return 'Email is already in use.';
  return 'That account identity is already in use.';
};
const createHttpError = (statusCode, message) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
};

const buildActivityDay = (value = new Date()) => {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toISOString().slice(0, 10);
};

const parseActivityDayStart = (value) => {
  const day = String(value || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return Number.NaN;
  return Date.parse(`${day}T00:00:00.000Z`);
};

const escapeRegex = (value) => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const getRequestOrigin = (req) => {
  const forwardedProto = sanitizeText(req.headers['x-forwarded-proto'], 20).toLowerCase();
  const protocol = forwardedProto || (req.secure ? 'https' : 'http');
  const host = sanitizeText(req.headers['x-forwarded-host'] || req.headers.host, 200);

  if (!host) return '';

  try {
    return new URL(`${protocol}://${host}`).origin;
  } catch {
    return '';
  }
};

const resolveAbsoluteUrl = (value) => {
  const raw = sanitizeText(value, 2000);
  if (!raw) return '';

  try {
    return new URL(raw).toString();
  } catch {
    return '';
  }
};

const escapeHtml = (value) =>
  String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const resolveEmailVerificationPageUrl = (req) => {
  const explicitVerifyUrl = resolveAbsoluteUrl(process.env.EMAIL_VERIFY_URL);
  if (explicitVerifyUrl) {
    return explicitVerifyUrl;
  }

  const loginPopupUrl = resolveAbsoluteUrl(
    process.env.LOGIN_POPUP_URL || process.env.PUBLIC_LOGIN_POPUP_URL || process.env.PUBLIC_LOGIN_URL
  );
  if (loginPopupUrl) {
    return new URL('verify.html', loginPopupUrl).toString();
  }

  const appBaseUrl = resolveAbsoluteUrl(
    process.env.APP_BASE_URL || process.env.PUBLIC_APP_URL || process.env.PUBLIC_BASE_URL
  );
  if (appBaseUrl) {
    return new URL(DEFAULT_EMAIL_VERIFY_PATH, appBaseUrl).toString();
  }

  if ((process.env.NODE_ENV || 'development') !== 'production') {
    const requestOrigin = getRequestOrigin(req);
    if (requestOrigin) {
      return new URL(DEFAULT_EMAIL_VERIFY_PATH, requestOrigin).toString();
    }
  }

  return '';
};

const buildEmailVerificationUrl = (req, token) => {
  const baseUrl = resolveEmailVerificationPageUrl(req);
  if (!baseUrl || !token) return '';

  const url = new URL(baseUrl);
  url.searchParams.set('token', token);
  return url.toString();
};

const prepareEmailVerification = (user) => {
  const verification = createEmailVerificationToken();

  user.isVerified = false;
  user.verificationToken = verification.hashedToken;
  user.verificationTokenExpires = verification.expiresAt;

  return verification;
};

const createPasswordResetToken = () => {
  const token = crypto.randomBytes(32).toString('hex');
  return {
    token,
    hashedToken: hashToken(token),
    expiresAt: new Date(Date.now() + PASSWORD_RESET_TTL_MS),
  };
};

const preparePasswordReset = (user) => {
  const reset = createPasswordResetToken();
  user.passwordResetToken = reset.hashedToken;
  user.passwordResetTokenExpires = reset.expiresAt;
  return reset;
};

const clearPasswordReset = (user) => {
  if (!user) return;
  user.passwordResetToken = '';
  user.passwordResetTokenExpires = null;
};

const buildVerificationEmailContent = (user, verificationUrl, expiresAt) => {
  const displayName = sanitizeText(user?.displayName || user?.email, 60) || 'there';
  const expiresLabel = new Date(expiresAt).toUTCString();
  const safeDisplayName = escapeHtml(displayName);
  const safeVerificationUrl = escapeHtml(verificationUrl);
  const safeExpiresLabel = escapeHtml(expiresLabel);

  return {
    subject: EMAIL_VERIFICATION_SUBJECT,
    text: [
      `Hi ${displayName},`,
      '',
      'Verify your Continental ID email address by opening this link:',
      verificationUrl,
      '',
      `This link expires on ${expiresLabel}.`,
    ].join('\n'),
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827;">
        <h1 style="margin-bottom:16px;">Verify your email</h1>
        <p>Hi ${safeDisplayName},</p>
        <p>Confirm your Continental ID email address to finish setting up your account.</p>
        <p>
          <a
            href="${safeVerificationUrl}"
            style="display:inline-block;padding:12px 18px;border-radius:8px;background:#111827;color:#ffffff;text-decoration:none;font-weight:700;"
          >
            Verify email
          </a>
        </p>
        <p>If the button does not work, copy and paste this link into your browser:</p>
        <p><a href="${safeVerificationUrl}">${safeVerificationUrl}</a></p>
        <p>This link expires on ${safeExpiresLabel}.</p>
      </div>
    `,
  };
};

const resolvePasswordResetPageUrl = (req) => {
  const explicitResetUrl = resolveAbsoluteUrl(
    process.env.PASSWORD_RESET_URL || process.env.PASSWORD_RESET_PAGE_URL
  );
  if (explicitResetUrl) {
    return explicitResetUrl;
  }

  const loginPopupUrl = resolveAbsoluteUrl(
    process.env.LOGIN_POPUP_URL || process.env.PUBLIC_LOGIN_POPUP_URL || process.env.PUBLIC_LOGIN_URL
  );
  if (loginPopupUrl) {
    return new URL('reset-password.html', loginPopupUrl).toString();
  }

  const appBaseUrl = resolveAbsoluteUrl(
    process.env.APP_BASE_URL || process.env.PUBLIC_APP_URL || process.env.PUBLIC_BASE_URL
  );
  if (appBaseUrl) {
    return new URL(DEFAULT_PASSWORD_RESET_PATH, appBaseUrl).toString();
  }

  if ((process.env.NODE_ENV || 'development') !== 'production') {
    const requestOrigin = getRequestOrigin(req);
    if (requestOrigin) {
      return new URL(DEFAULT_PASSWORD_RESET_PATH, requestOrigin).toString();
    }
  }

  return '';
};

const buildPasswordResetUrl = (req, token) => {
  const baseUrl = resolvePasswordResetPageUrl(req);
  if (!baseUrl || !token) return '';

  const url = new URL(baseUrl);
  url.searchParams.set('token', token);
  return url.toString();
};

const buildPasswordResetEmailContent = (user, resetUrl, expiresAt) => {
  const displayName = sanitizeText(user?.displayName || user?.email, 60) || 'there';
  const expiresLabel = new Date(expiresAt).toUTCString();
  const safeDisplayName = escapeHtml(displayName);
  const safeResetUrl = escapeHtml(resetUrl);
  const safeExpiresLabel = escapeHtml(expiresLabel);

  return {
    subject: PASSWORD_RESET_SUBJECT,
    text: [
      `Hi ${displayName},`,
      '',
      'Open this link to reset your Continental ID password:',
      resetUrl,
      '',
      `This link expires on ${expiresLabel}.`,
      'If you did not request this, you can ignore this message.',
    ].join('\n'),
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827;">
        <h1 style="margin-bottom:16px;">Reset your password</h1>
        <p>Hi ${safeDisplayName},</p>
        <p>We received a request to reset your Continental ID password.</p>
        <p>
          <a
            href="${safeResetUrl}"
            style="display:inline-block;padding:12px 18px;border-radius:8px;background:#111827;color:#ffffff;text-decoration:none;font-weight:700;"
          >
            Reset password
          </a>
        </p>
        <p>If the button does not work, copy and paste this link into your browser:</p>
        <p><a href="${safeResetUrl}">${safeResetUrl}</a></p>
        <p>This link expires on ${safeExpiresLabel}.</p>
      </div>
    `,
  };
};

const serializeVerificationDelivery = (delivery) => ({
  sent: Boolean(delivery?.sent),
});

const getVerificationDeliveryMessage = (successMessage, failureMessage, delivery) => {
  return delivery?.sent ? successMessage : failureMessage;
};

const sendVerificationEmail = async (user, req, verification) => {
  if (!user?.email || !verification?.token) {
    return { sent: false };
  }

  const verificationUrl = buildEmailVerificationUrl(req, verification.token);
  if (!verificationUrl) {
    console.warn('Verification email URL is not configured; skipping verification email.');
    return { sent: false };
  }

  try {
    const emailContent = buildVerificationEmailContent(user, verificationUrl, verification.expiresAt);
    const response = await sendEmail({
      to: user.email,
      subject: emailContent.subject,
      text: emailContent.text,
      html: emailContent.html,
    });

    return {
      sent: !response?.skipped,
      id: sanitizeText(response?.id, 120),
    };
  } catch (err) {
    console.error('Verification email delivery error:', err);
    return { sent: false };
  }
};

const sendPasswordResetEmail = async (user, req, reset) => {
  if (!user?.email || !reset?.token) {
    return { sent: false };
  }

  const resetUrl = buildPasswordResetUrl(req, reset.token);
  if (!resetUrl) {
    console.warn('Password reset URL is not configured; skipping password reset email.');
    return { sent: false };
  }

  try {
    const emailContent = buildPasswordResetEmailContent(user, resetUrl, reset.expiresAt);
    const response = await sendEmail({
      to: user.email,
      subject: emailContent.subject,
      text: emailContent.text,
      html: emailContent.html,
    });

    return {
      sent: !response?.skipped,
      id: sanitizeText(response?.id, 120),
    };
  } catch (err) {
    console.error('Password reset email delivery error:', err);
    return { sent: false };
  }
};

const buildSecurityEmailContent = ({ title, intro, details = [] }) => {
  const safeTitle = escapeHtml(title || 'Security alert');
  const safeIntro = escapeHtml(intro || 'A security-sensitive action was detected on your account.');
  const normalizedDetails = Array.isArray(details)
    ? details.map((item) => sanitizeText(item, 240)).filter(Boolean)
    : [];

  return {
    text: [
      title || 'Security alert',
      '',
      intro || 'A security-sensitive action was detected on your account.',
      '',
      ...normalizedDetails.map((item) => `- ${item}`),
    ].join('\n'),
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827;">
        <h1 style="margin-bottom:16px;">${safeTitle}</h1>
        <p>${safeIntro}</p>
        ${
          normalizedDetails.length
            ? `<ul>${normalizedDetails.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`
            : ''
        }
      </div>
    `,
  };
};

const shouldSendSecurityNotifications = (user) =>
  Boolean(
    user?.email &&
      (hasOwn(user?.preferences?.notifications || {}, 'security')
        ? user?.preferences?.notifications?.security
        : DEFAULT_NOTIFICATIONS.security)
  );

const shouldSendLoginAlert = (user) =>
  shouldSendSecurityNotifications(user) &&
  Boolean(hasOwn(user?.security || {}, 'loginAlerts') ? user?.security?.loginAlerts : true);

const sendSecurityAlertEmail = async (user, subject, title, intro, details = []) => {
  if (!shouldSendSecurityNotifications(user)) {
    return { sent: false };
  }

  try {
    const emailContent = buildSecurityEmailContent({ title, intro, details });
    const response = await sendEmail({
      to: user.email,
      subject,
      text: emailContent.text,
      html: emailContent.html,
    });

    return {
      sent: !response?.skipped,
      id: sanitizeText(response?.id, 120),
    };
  } catch (err) {
    console.error('Security alert email delivery error:', err);
    return { sent: false };
  }
};

const sanitizeAuditMeta = (value = {}) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }

  const next = {};

  for (const [rawKey, rawValue] of Object.entries(value).slice(0, 10)) {
    const key = sanitizeText(rawKey, 40);
    if (!key) continue;
    if (rawValue === undefined || rawValue === null || rawValue === '') continue;

    if (typeof rawValue === 'number' || typeof rawValue === 'boolean') {
      next[key] = rawValue;
      continue;
    }

    next[key] = sanitizeText(rawValue, 160);
  }

  return next;
};

const serializeAuditEvent = (event = {}) => ({
  at: event?.at || null,
  type: sanitizeText(event?.type, 60),
  message: sanitizeText(event?.message, 240),
  ip: sanitizeText(event?.ip, 80),
  userAgent: sanitizeText(event?.userAgent, 300),
  meta: sanitizeAuditMeta(event?.meta),
});

const appendAuditEvent = (user, req, type, message, meta = {}) => {
  if (!user) return;

  const events = Array.isArray(user.auditEvents)
    ? user.auditEvents.map((event) => serializeAuditEvent(event)).filter((event) => event.type)
    : [];

  events.push(
    serializeAuditEvent({
      at: new Date(),
      type,
      message,
      ip: parseClientIp(req),
      userAgent: parseUserAgent(req),
      meta,
    })
  );

  user.auditEvents = events.slice(-MAX_AUDIT_EVENTS);
};

const normalizeDeviceFingerprintSource = (userAgent = '') =>
  sanitizeText(String(userAgent || '').toLowerCase().replace(/\/\d+(?:\.\d+)*/g, ''), 260) ||
  'unknown-device';

const buildDeviceFingerprint = (userAgent = '') => hashToken(normalizeDeviceFingerprintSource(userAgent));

const rememberKnownDevice = (user, req, requestedLabel = '') => {
  const userAgent = parseUserAgent(req);
  const fingerprint = buildDeviceFingerprint(userAgent);
  const label = buildSessionLabel(requestedLabel, userAgent);
  const now = new Date();
  const ip = parseClientIp(req);
  const devices = Array.isArray(user.knownDevices) ? [...user.knownDevices] : [];
  const existingIndex = devices.findIndex(
    (device) => sanitizeText(device?.fingerprint, 128) === fingerprint
  );

  const nextDevice = {
    fingerprint,
    label,
    firstSeenAt: now,
    lastSeenAt: now,
    lastIp: ip,
    userAgent,
  };

  if (existingIndex >= 0) {
    const currentDevice = devices[existingIndex];
    devices[existingIndex] = {
      ...currentDevice,
      fingerprint,
      label: sanitizeText(currentDevice?.label || label, 60) || label,
      lastSeenAt: now,
      lastIp: ip,
      userAgent,
    };
  } else {
    devices.push(nextDevice);
  }

  devices.sort((left, right) => {
    const leftTime = new Date(left?.lastSeenAt || 0).getTime();
    const rightTime = new Date(right?.lastSeenAt || 0).getTime();
    return leftTime - rightTime;
  });

  while (devices.length > MAX_KNOWN_DEVICES) {
    devices.shift();
  }

  user.knownDevices = devices;

  return {
    fingerprint,
    isNewDevice: existingIndex < 0,
    device:
      devices.find((device) => sanitizeText(device?.fingerprint, 128) === fingerprint) || nextDevice,
  };
};

const isCrossSiteRequest = (req) => {
  const requestOrigin = getRequestOrigin(req);
  const originHeader = sanitizeText(req.headers.origin, 240);

  if (!requestOrigin || !originHeader) {
    return false;
  }

  try {
    return new URL(originHeader).origin !== requestOrigin;
  } catch {
    return false;
  }
};

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

const sanitizeAvatar = (value, fallback = '') => {
  const raw = String(value || '').trim();
  if (!raw) return '';

  if (raw.length <= AVATAR_DATA_URL_MAX_LENGTH && AVATAR_DATA_URL_PATTERN.test(raw)) {
    return raw;
  }

  const normalized = sanitizeText(raw, 2400);
  if (!normalized) return '';

  const withProtocol = /^https?:\/\//i.test(normalized) ? normalized : `https://${normalized}`;

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

const sanitizeHeadline = (value, fallback = '') => sanitizeText(value, 100) || fallback;
const sanitizePronouns = (value, fallback = '') => sanitizeText(value, 40) || fallback;

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
    avatar: hasOwn(incoming, 'avatar')
      ? sanitizeAvatar(incoming.avatar, sanitizeAvatar(currentProfile.avatar, ''))
      : sanitizeAvatar(currentProfile.avatar, ''),
    headline: hasOwn(incoming, 'headline')
      ? sanitizeHeadline(incoming.headline, sanitizeHeadline(currentProfile.headline, ''))
      : sanitizeHeadline(currentProfile.headline, ''),
    pronouns: hasOwn(incoming, 'pronouns')
      ? sanitizePronouns(incoming.pronouns, sanitizePronouns(currentProfile.pronouns, ''))
      : sanitizePronouns(currentProfile.pronouns, ''),
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
  const crossSite = isCrossSiteRequest(req);

  return {
    httpOnly: true,
    secure: isSecure,
    sameSite: isSecure ? (crossSite ? 'None' : 'Strict') : 'Lax',
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
    {
      algorithm: 'HS256',
      expiresIn: ACCESS_TOKEN_TTL,
    }
  );

const signRefreshToken = (user, sid, refreshTokenId) =>
  jwt.sign(
    {
      userId: toObjectIdString(user._id),
      tokenVersion: user.refreshTokenVersion,
      sid: sanitizeText(sid, 120) || undefined,
      jti: sanitizeText(refreshTokenId, 120) || undefined,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: REFRESH_TOKEN_TTL,
    }
  );

const appendRecentLogin = (user, req) => {
  const entry = {
    at: new Date(),
    ip: parseClientIp(req),
    userAgent: parseUserAgent(req),
  };
  const cutoffMs = Date.now() - LOGIN_ACTIVITY_RETENTION_DAYS * DAY_MS;
  const day = buildActivityDay(entry.at);

  user.lastLoginAt = entry.at;
  user.lastLoginIp = entry.ip;

  const list = Array.isArray(user.recentLogins)
    ? user.recentLogins.filter((item) => {
        const timestamp = new Date(item?.at || '').getTime();
        return !Number.isNaN(timestamp) && timestamp >= cutoffMs;
      })
    : [];
  list.push(entry);

  user.recentLogins = list.slice(-MAX_RECENT_LOGIN_EVENTS);

  const loginDayCounts = Array.isArray(user.loginDayCounts)
    ? user.loginDayCounts
        .map((item) => ({
          day: buildActivityDay(item?.day),
          count: Math.max(0, Math.trunc(Number(item?.count || 0))),
        }))
        .filter((item) => {
          const dayStart = parseActivityDayStart(item.day);
          return item.day && item.count > 0 && !Number.isNaN(dayStart) && dayStart >= cutoffMs;
        })
    : [];

  const existingDayIndex = loginDayCounts.findIndex((item) => item.day === day);
  if (existingDayIndex >= 0) {
    loginDayCounts[existingDayIndex].count += 1;
  } else if (day) {
    loginDayCounts.push({ day, count: 1 });
  }

  loginDayCounts.sort((a, b) => a.day.localeCompare(b.day));
  user.loginDayCounts = loginDayCounts;
};

const createSessionId = () => crypto.randomUUID();
const createRefreshTokenId = () => crypto.randomUUID();

const upsertRefreshSession = (user, req, sid = '', requestedLabel = '', options = {}) => {
  const sessions = Array.isArray(user.refreshSessions) ? [...user.refreshSessions] : [];
  const sessionId = sanitizeText(sid, 120) || createSessionId();
  const now = new Date();
  const ip = parseClientIp(req);
  const userAgent = parseUserAgent(req);
  const label = buildSessionLabel(requestedLabel, userAgent);
  const deviceFingerprint = sanitizeText(options.deviceFingerprint, 128);
  const currentRefreshTokenId = sanitizeText(options.currentRefreshTokenId, 120);
  const previousRefreshTokenId = sanitizeText(options.previousRefreshTokenId, 120);
  const hasDeviceFingerprint = hasOwn(options, 'deviceFingerprint');
  const hasCurrentRefreshTokenId = hasOwn(options, 'currentRefreshTokenId');
  const hasPreviousRefreshTokenId = hasOwn(options, 'previousRefreshTokenId');
  const hasPreviousRefreshTokenGraceUntil = hasOwn(options, 'previousRefreshTokenGraceUntil');
  const previousRefreshTokenGraceUntil =
    options.previousRefreshTokenGraceUntil instanceof Date
      ? options.previousRefreshTokenGraceUntil
      : options.previousRefreshTokenGraceUntil
        ? new Date(options.previousRefreshTokenGraceUntil)
        : null;

  const existingIndex = sessions.findIndex(
    (session) => sanitizeText(session.sid, 120) === sessionId
  );

  if (existingIndex >= 0) {
    const nextSession = {
      ...sessions[existingIndex],
      sid: sessionId,
      label: label || sessions[existingIndex].label || 'Browser session',
      createdAt: sessions[existingIndex].createdAt || now,
      lastUsedAt: now,
      ip,
      userAgent,
    };

    if (hasDeviceFingerprint) {
      nextSession.deviceFingerprint = deviceFingerprint;
    }
    if (hasCurrentRefreshTokenId) {
      nextSession.currentRefreshTokenId = currentRefreshTokenId;
    }
    if (hasPreviousRefreshTokenId) {
      nextSession.previousRefreshTokenId = previousRefreshTokenId;
    }
    if (hasPreviousRefreshTokenGraceUntil) {
      nextSession.previousRefreshTokenGraceUntil = previousRefreshTokenGraceUntil;
    }

    sessions[existingIndex] = nextSession;
  } else {
    sessions.push({
      sid: sessionId,
      label,
      createdAt: now,
      lastUsedAt: now,
      ip,
      userAgent,
      deviceFingerprint,
      currentRefreshTokenId,
      previousRefreshTokenId,
      previousRefreshTokenGraceUntil,
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

const findRefreshSession = (user, sid) => {
  const sessionId = sanitizeText(sid, 120);
  if (!sessionId) return null;

  const sessions = Array.isArray(user.refreshSessions) ? user.refreshSessions : [];
  return (
    sessions.find((session) => sanitizeText(session?.sid, 120) === sessionId) || null
  );
};

const buildTokenPair = (user, sid, refreshTokenId) => {
  const accessToken = signToken(user, sid);
  const refreshToken = signRefreshToken(user, sid, refreshTokenId);

  return {
    accessToken,
    refreshToken,
    refreshTokenId: sanitizeText(refreshTokenId, 120),
  };
};

const createTrackedRefreshSession = (user, req, requestedLabel = '', deviceFingerprint = '') => {
  const sid = createSessionId();
  const refreshTokenId = createRefreshTokenId();
  upsertRefreshSession(user, req, sid, requestedLabel, {
    deviceFingerprint,
    currentRefreshTokenId: refreshTokenId,
    previousRefreshTokenId: '',
    previousRefreshTokenGraceUntil: null,
  });

  return {
    sid,
    ...buildTokenPair(user, sid, refreshTokenId),
  };
};

const rotateRefreshSessionToken = (user, req, sid, session, requestedLabel = '') => {
  const nextRefreshTokenId = createRefreshTokenId();
  const currentRefreshTokenId = sanitizeText(session?.currentRefreshTokenId, 120);

  upsertRefreshSession(user, req, sid, requestedLabel, {
    deviceFingerprint: sanitizeText(session?.deviceFingerprint, 128),
    currentRefreshTokenId: nextRefreshTokenId,
    previousRefreshTokenId: currentRefreshTokenId,
    previousRefreshTokenGraceUntil: currentRefreshTokenId
      ? new Date(Date.now() + REFRESH_TOKEN_REPLAY_GRACE_MS)
      : null,
  });

  return buildTokenPair(user, sid, nextRefreshTokenId);
};

const reissueCurrentRefreshSession = (user, req, sid, session, requestedLabel = '') => {
  const currentRefreshTokenId =
    sanitizeText(session?.currentRefreshTokenId, 120) || createRefreshTokenId();

  upsertRefreshSession(user, req, sid, requestedLabel, {
    deviceFingerprint: sanitizeText(session?.deviceFingerprint, 128),
    currentRefreshTokenId,
  });

  return buildTokenPair(user, sid, currentRefreshTokenId);
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

const getKnownDeviceMap = (user) =>
  new Map(
    (Array.isArray(user?.knownDevices) ? user.knownDevices : [])
      .map((device) => [sanitizeText(device?.fingerprint, 128), device])
      .filter(([fingerprint]) => fingerprint)
  );

const serializeSession = (session, currentSid = '', knownDevice = null) => {
  const sid = sanitizeText(session?.sid, 120);
  const deviceFirstSeenAt = knownDevice?.firstSeenAt ? new Date(knownDevice.firstSeenAt).getTime() : 0;
  const sessionCreatedAt = session?.createdAt ? new Date(session.createdAt).getTime() : 0;
  const newDevice =
    Boolean(deviceFirstSeenAt && sessionCreatedAt) &&
    Math.abs(deviceFirstSeenAt - sessionCreatedAt) <= NEW_DEVICE_SESSION_WINDOW_MS;
  return {
    sid,
    label: sanitizeText(session?.label, 60) || 'Browser session',
    createdAt: session?.createdAt || null,
    lastUsedAt: session?.lastUsedAt || null,
    ip: sanitizeText(session?.ip, 80),
    userAgent: sanitizeText(session?.userAgent, 300),
    recognized: Boolean(knownDevice),
    newDevice,
    deviceLabel: sanitizeText(knownDevice?.label, 60) || '',
    current: Boolean(sid && sid === sanitizeText(currentSid, 120)),
  };
};

const isUsernameTaken = async (username, userId) => {
  const candidate = normalizeUsername(username);
  if (!candidate) return false;

  const query = { username: candidate };
  if (userId) {
    query._id = { $ne: userId };
  }

  return Boolean(await User.exists(query));
};

const applyUsernameChange = async (user, username) => {
  const normalized = normalizeUsername(username);

  if (!normalized) {
    return ensureStoredUsername(user);
  }

  if (!isValidUsername(normalized)) {
    throw createHttpError(400, USERNAME_VALIDATION_MESSAGE);
  }

  const taken = await isUsernameTaken(normalized, user?._id);
  if (taken) {
    throw createHttpError(409, 'Username is already in use.');
  }

  if (user.username !== normalized) {
    user.username = normalized;
    return true;
  }

  return false;
};

const profileCompletion = (user) => {
  const fields = [
    getDisplayableUsername(user),
    sanitizeText(user.displayName, 60),
    sanitizeText(user.email, 120),
    sanitizeAvatar(user.profile?.avatar, ''),
    sanitizeHeadline(user.profile?.headline, ''),
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
  const activitySummary = buildActivitySummary(
    Array.isArray(user.recentLogins) ? user.recentLogins : [],
    Array.isArray(user.loginDayCounts) ? user.loginDayCounts : []
  );

  return {
    userId: toObjectIdString(user._id),
    continentalId: toObjectIdString(user._id),
    email: user.email,
    username: getDisplayableUsername(user),
    handle: `@${getDisplayableUsername(user)}`,
    displayName: user.displayName || 'User',
    isVerified: Boolean(user.isVerified),
    createdAt: user.createdAt || null,
    updatedAt: user.updatedAt || null,
    lastLoginAt: user.lastLoginAt || null,
    lastLoginIp: user.lastLoginIp || null,
    recentLogins: Array.isArray(user.recentLogins)
      ? user.recentLogins.slice(-RECENT_LOGIN_RESPONSE_LIMIT).reverse()
      : [],
    auditEvents: Array.isArray(user.auditEvents)
      ? user.auditEvents.slice(-MAX_AUDIT_EVENTS).reverse().map((event) => serializeAuditEvent(event))
      : [],
    activitySummary,
    profile: {
      avatar: sanitizeAvatar(user.profile?.avatar, ''),
      headline: sanitizeHeadline(user.profile?.headline, ''),
      pronouns: sanitizePronouns(user.profile?.pronouns, ''),
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
      loginAlerts: Boolean(hasOwn(user.security || {}, 'loginAlerts') ? user.security?.loginAlerts : true),
      passwordChangedAt: user.security?.passwordChangedAt || null,
      activeSessions: Array.isArray(user.refreshSessions) ? user.refreshSessions.length : 0,
      knownDevices: Array.isArray(user.knownDevices) ? user.knownDevices.length : 0,
    },
  };
};

const buildPublicLinkedAccounts = (linkedAccounts = {}) => {
  const next = {};

  for (const provider of LINKED_PROVIDERS) {
    const value = sanitizeText(linkedAccounts?.[provider], 120);
    if (value) {
      next[provider] = value;
    }
  }

  return next;
};

const buildPublicProfilePayload = (user) => ({
  username: getDisplayableUsername(user),
  handle: `@${getDisplayableUsername(user)}`,
  displayName: sanitizeText(user?.displayName, 60) || 'User',
  createdAt: user?.createdAt || null,
  updatedAt: user?.updatedAt || null,
  profile: {
    avatar: sanitizeAvatar(user?.profile?.avatar, ''),
    headline: sanitizeHeadline(user?.profile?.headline, ''),
    pronouns: sanitizePronouns(user?.profile?.pronouns, ''),
    bio: sanitizeText(user?.profile?.bio, 320),
    location: sanitizeText(user?.profile?.location, 120),
    website: sanitizeText(user?.profile?.website, 240),
    timezone: sanitizeTimezone(user?.profile?.timezone, 'UTC'),
    language: sanitizeLanguage(user?.profile?.language, 'en'),
  },
  linkedAccounts: buildPublicLinkedAccounts(user?.linkedAccounts),
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

const buildActivitySummary = (recentLogins = [], dailyCounts = []) => {
  const now = Date.now();
  const sevenDaysAgo = now - 7 * DAY_MS;
  const thirtyDaysAgo = now - 30 * DAY_MS;

  const uniqueIps = new Set();

  for (const entry of recentLogins) {
    const timestamp = new Date(entry?.at || '').getTime();
    if (Number.isNaN(timestamp)) continue;

    const ip = sanitizeText(entry?.ip, 80);
    if (ip) uniqueIps.add(ip);
  }

  const normalizedDailyCounts = Array.isArray(dailyCounts)
    ? dailyCounts
        .map((entry) => ({
          day: buildActivityDay(entry?.day),
          count: Math.max(0, Math.trunc(Number(entry?.count || 0))),
        }))
        .filter((entry) => entry.day && entry.count > 0 && !Number.isNaN(parseActivityDayStart(entry.day)))
        .sort((a, b) => a.day.localeCompare(b.day))
    : [];

  if (normalizedDailyCounts.length > 0) {
    let last7Days = 0;
    let last30Days = 0;

    for (const entry of normalizedDailyCounts) {
      const dayStart = parseActivityDayStart(entry.day);
      if (dayStart >= sevenDaysAgo) last7Days += entry.count;
      if (dayStart >= thirtyDaysAgo) last30Days += entry.count;
    }

    return {
      last7Days,
      last30Days,
      uniqueIps: uniqueIps.size,
      recentDays: normalizedDailyCounts.slice(-7),
    };
  }

  let last7Days = 0;
  let last30Days = 0;
  const byDay = new Map();

  for (const entry of recentLogins) {
    const timestamp = new Date(entry?.at || '').getTime();
    if (Number.isNaN(timestamp)) continue;

    if (timestamp >= sevenDaysAgo) last7Days += 1;
    if (timestamp >= thirtyDaysAgo) last30Days += 1;

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

const FULL_USER_SELECT_FIELDS =
  'email username displayName isVerified verificationToken verificationTokenExpires passwordResetToken passwordResetTokenExpires lastLoginAt lastLoginIp recentLogins loginDayCounts knownDevices auditEvents profile linkedAccounts preferences security refreshTokenVersion refreshSessions createdAt updatedAt password';

const getUserById = async (id, { ensureIdentity = true } = {}) => {
  const user = await User.findById(id).select(FULL_USER_SELECT_FIELDS);

  if (user && ensureIdentity) {
    const changed = await ensureUserIdentityFields(user);
    if (changed) {
      await user.save();
    }
  }

  return user;
};

const loginRateKey = (identifier, req) => `${normalizeLoginIdentifier(identifier)}|${parseClientIp(req)}`;

const findUserByLoginIdentifier = async (identifier) => {
  const normalized = normalizeLoginIdentifier(identifier);
  if (!normalized) return null;

  if (isValidEmail(normalized)) {
    return User.findOne({ email: normalized });
  }

  if (isValidUsername(normalized)) {
    return User.findOne({ username: normalized });
  }

  return null;
};

const getLoginThrottleState = async (key) => {
  const now = Date.now();
  const entry = await LoginThrottle.findOne({ key }).select('windowStartedAt blockedUntil');

  if (!entry) {
    return { blocked: false, retryAfterSec: 0 };
  }

  const blockedUntil = entry.blockedUntil ? new Date(entry.blockedUntil).getTime() : 0;
  if (blockedUntil > now) {
    return {
      blocked: true,
      retryAfterSec: Math.max(1, Math.ceil((blockedUntil - now) / 1000)),
    };
  }

  const windowStartedAt = entry.windowStartedAt ? new Date(entry.windowStartedAt).getTime() : 0;
  if (!windowStartedAt || now - windowStartedAt > LOGIN_RATE_WINDOW_MS) {
    await LoginThrottle.deleteOne({ key });
  }

  return { blocked: false, retryAfterSec: 0 };
};

const registerLoginFailure = async (key) => {
  const now = Date.now();
  const current = await LoginThrottle.findOne({ key });

  if (
    !current ||
    !current.windowStartedAt ||
    now - new Date(current.windowStartedAt).getTime() > LOGIN_RATE_WINDOW_MS
  ) {
    try {
      await LoginThrottle.findOneAndUpdate(
        { key },
        {
          key,
          windowStartedAt: new Date(now),
          count: 1,
          blockedUntil: null,
          expiresAt: buildLoginThrottleExpiry(now),
        },
        {
          new: true,
          upsert: true,
          setDefaultsOnInsert: true,
        }
      );
    } catch (err) {
      if (!isDuplicateKeyError(err)) {
        throw err;
      }

      const retry = await LoginThrottle.findOne({ key });
      if (!retry) {
        throw err;
      }

      retry.count += 1;
      retry.expiresAt = buildLoginThrottleExpiry(now);
      if (retry.count >= LOGIN_RATE_MAX_ATTEMPTS) {
        retry.blockedUntil = new Date(now + LOGIN_BLOCK_MS);
      }
      await retry.save();
    }
    return;
  }

  current.count += 1;
  current.expiresAt = buildLoginThrottleExpiry(now);

  if (current.count >= LOGIN_RATE_MAX_ATTEMPTS) {
    current.blockedUntil = new Date(now + LOGIN_BLOCK_MS);
  }

  await current.save();
};

const clearLoginFailures = async (key) => {
  await LoginThrottle.deleteOne({ key });
};

const applyEmailChange = async (user, email, currentPassword) => {
  const nextEmail = normalizeEmail(email);
  const currentEmail = normalizeEmail(user?.email);

  if (!nextEmail || nextEmail === currentEmail) {
    return false;
  }

  if (!isValidEmail(nextEmail)) {
    throw createHttpError(400, 'Please provide a valid email address.');
  }

  if (typeof currentPassword !== 'string' || currentPassword.length === 0) {
    throw createHttpError(400, 'Current password is required to change your email.');
  }

  const matches = await user.comparePassword(currentPassword);
  if (!matches) {
    throw createHttpError(400, 'Current password is incorrect.');
  }

  const existing = await User.findOne({ email: nextEmail }).select('_id');
  if (existing && toObjectIdString(existing._id) !== toObjectIdString(user._id)) {
    throw createHttpError(409, 'Email is already in use.');
  }

  user.email = nextEmail;
  return true;
};

const revokeRefreshSessionForReplay = async (user, sid) => {
  if (!user || !sid) return;
  if (!removeRefreshSession(user, sid)) return;
  await user.save();
};

const resolveRefreshSessionFromCookie = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return null;

  let payload;
  try {
    payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, {
      algorithms: ['HS256'],
    });
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
  const refreshTokenId = sanitizeText(payload.jti, 120);

  if (sidFromToken) {
    const session = findRefreshSession(user, sidFromToken);
    if (!session) {
      clearRefreshCookie(res, req);
      return null;
    }

    const currentRefreshTokenId = sanitizeText(session.currentRefreshTokenId, 120);
    const previousRefreshTokenId = sanitizeText(session.previousRefreshTokenId, 120);
    const previousRefreshTokenGraceUntil = session.previousRefreshTokenGraceUntil
      ? new Date(session.previousRefreshTokenGraceUntil).getTime()
      : 0;

    if (currentRefreshTokenId) {
      if (refreshTokenId === currentRefreshTokenId) {
        return { user, sid: sidFromToken, session, tokenState: 'current' };
      }

      if (
        refreshTokenId &&
        previousRefreshTokenId &&
        refreshTokenId === previousRefreshTokenId &&
        previousRefreshTokenGraceUntil > Date.now()
      ) {
        return { user, sid: sidFromToken, session, tokenState: 'grace' };
      }

      if (refreshTokenId) {
        await revokeRefreshSessionForReplay(user, sidFromToken);
        clearRefreshCookie(res, req);
        return { replayDetected: true };
      }

      clearRefreshCookie(res, req);
      return null;
    }

    if (refreshTokenId) {
      upsertRefreshSession(user, req, sidFromToken, '', {
        currentRefreshTokenId: refreshTokenId,
        previousRefreshTokenId: '',
        previousRefreshTokenGraceUntil: null,
      });
      return {
        user,
        sid: sidFromToken,
        session: findRefreshSession(user, sidFromToken),
        tokenState: 'current',
      };
    }

    return { user, sid: sidFromToken, session, tokenState: 'legacy' };
  }

  return { user, sid: '', session: null, tokenState: 'legacy' };
};

exports.register = async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;
  const displayName = sanitizeDisplayName(req.body?.displayName, email);
  const requestedUsername = req.body?.username;

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

    if (hasOwn(req.body || {}, 'username') && !normalizeUsername(requestedUsername)) {
      return res.status(400).json({ message: USERNAME_VALIDATION_MESSAGE });
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

    await applyUsernameChange(user, requestedUsername);
    const device = rememberKnownDevice(user, req, req.body?.deviceLabel);
    const verification = prepareEmailVerification(user);
    appendRecentLogin(user, req);
    appendAuditEvent(user, req, 'register', 'Account created.', {
      username: getDisplayableUsername(user),
    });
    const sessionTokens = createTrackedRefreshSession(
      user,
      req,
      req.body?.deviceLabel,
      device.fingerprint
    );
    await user.save();
    const verificationDelivery = await sendVerificationEmail(user, req, verification);

    res.cookie('refreshToken', sessionTokens.refreshToken, buildCookieOptions(req));

    return sendUserResponse(
      res,
      201,
      getVerificationDeliveryMessage(
        'Registration successful. Check your inbox to verify your email.',
        'Registration successful, but the verification email could not be sent right now.',
        verificationDelivery
      ),
      user,
      {
        verificationEmail: serializeVerificationDelivery(verificationDelivery),
        token: sessionTokens.accessToken,
        accessToken: sessionTokens.accessToken,
      }
    );
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    if (isDuplicateKeyError(err)) {
      return res.status(409).json({ message: getDuplicateUserFieldMessage(err) });
    }
    console.error('Register error:', err);
    return res.status(500).json({ message: 'Registration failed.' });
  }
};

exports.login = async (req, res) => {
  const identifier = normalizeLoginIdentifier(
    req.body?.identifier || req.body?.email || req.body?.username
  );
  const password = req.body?.password;

  const rateKey = loginRateKey(identifier, req);
  const throttle = await getLoginThrottleState(rateKey);
  if (throttle.blocked) {
    return res.status(429).json({
      message: `Too many failed login attempts. Try again in ${throttle.retryAfterSec} seconds.`,
      retryAfterSec: throttle.retryAfterSec,
    });
  }

  try {
    if ((!isValidEmail(identifier) && !isValidUsername(identifier)) || typeof password !== 'string') {
      await registerLoginFailure(rateKey);
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const user = await findUserByLoginIdentifier(identifier);
    if (!user) {
      await registerLoginFailure(rateKey);
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      await registerLoginFailure(rateKey);
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    await clearLoginFailures(rateKey);

    await ensureUserIdentityFields(user);
    const device = rememberKnownDevice(user, req, req.body?.deviceLabel);
    appendRecentLogin(user, req);
    appendAuditEvent(
      user,
      req,
      'login',
      device.isNewDevice ? 'Signed in from a new device.' : 'Signed in.',
      {
        newDevice: device.isNewDevice,
      }
    );
    const sessionTokens = createTrackedRefreshSession(
      user,
      req,
      req.body?.deviceLabel,
      device.fingerprint
    );
    await user.save();

    if (device.isNewDevice && shouldSendLoginAlert(user)) {
      await sendSecurityAlertEmail(
        user,
        'New device sign-in to Continental ID',
        'New device sign-in detected',
        'A sign-in from a device we had not seen before was detected on your account.',
        [
          `Time: ${new Date().toUTCString()}`,
          `IP address: ${parseClientIp(req) || 'Unknown'}`,
          `Device: ${buildSessionLabel(req.body?.deviceLabel, parseUserAgent(req))}`,
        ]
      );
    }

    res.cookie('refreshToken', sessionTokens.refreshToken, buildCookieOptions(req));

    return sendUserResponse(res, 200, 'Login successful.', user, {
      token: sessionTokens.accessToken,
      accessToken: sessionTokens.accessToken,
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Login failed.' });
  }
};

exports.logout = async (req, res) => {
  try {
    const session = await resolveRefreshSessionFromCookie(req, res);
    if (session?.user) {
      if (session.sid) {
        removeRefreshSession(session.user, session.sid);
      } else {
        session.user.refreshTokenVersion += 1;
        session.user.refreshSessions = [];
      }
      appendAuditEvent(
        session.user,
        req,
        'logout',
        session.sid ? 'Signed out of the current session.' : 'Signed out of all sessions.'
      );
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

exports.requestPasswordReset = async (req, res) => {
  const identifier = normalizeLoginIdentifier(
    req.body?.identifier || req.body?.email || req.body?.username
  );
  const genericMessage =
    'If an account matches that sign-in, a password reset link will be sent shortly.';

  try {
    if (!identifier || (!isValidEmail(identifier) && !isValidUsername(identifier))) {
      return res.status(200).json({ message: genericMessage });
    }

    const user = await findUserByLoginIdentifier(identifier);
    if (!user) {
      return res.status(200).json({ message: genericMessage });
    }

    await ensureUserIdentityFields(user);
    const reset = preparePasswordReset(user);
    appendAuditEvent(user, req, 'password_reset_requested', 'Password reset requested.');
    await user.save();
    await sendPasswordResetEmail(user, req, reset);

    return res.status(200).json({ message: genericMessage });
  } catch (err) {
    console.error('Password reset request error:', err);
    return res.status(200).json({ message: genericMessage });
  }
};

exports.resetPassword = async (req, res) => {
  const token = sanitizeText(req.body?.token, 200);
  const newPassword = req.body?.newPassword || '';

  if (!token) {
    return res.status(400).json({ message: 'Password reset token is required.' });
  }

  if (!isStrongPassword(newPassword)) {
    return res.status(400).json({
      message:
        'New password must be at least 8 characters and include uppercase, lowercase, and a number.',
    });
  }

  try {
    const user = await User.findOne({
      passwordResetToken: hashToken(token),
      passwordResetTokenExpires: { $gt: Date.now() },
    }).select(FULL_USER_SELECT_FIELDS);

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired password reset link.' });
    }

    clearPasswordReset(user);
    user.password = newPassword;
    user.refreshTokenVersion += 1;
    user.refreshSessions = [];
    appendAuditEvent(user, req, 'password_reset_completed', 'Password reset completed.');
    await user.save();

    await sendSecurityAlertEmail(
      user,
      'Your Continental ID password was reset',
      'Password reset completed',
      'Your Continental ID password was just reset.',
      [
        `Time: ${new Date().toUTCString()}`,
        `IP address: ${parseClientIp(req) || 'Unknown'}`,
      ]
    );

    return res.status(200).json({
      message: 'Password reset successful. You can now sign in with your new password.',
    });
  } catch (err) {
    console.error('Password reset completion error:', err);
    return res.status(500).json({ message: 'Failed to reset password.' });
  }
};

exports.searchPublicProfiles = async (req, res) => {
  const query = sanitizeText(req.query?.q, 60);

  try {
    if (query.length < 2) {
      return res.json({ message: 'Search loaded.', results: [] });
    }

    const regex = new RegExp(escapeRegex(query), 'i');
    const users = await User.find({
      'preferences.profilePublic': true,
      'preferences.searchable': true,
      $or: [
        { username: regex },
        { displayName: regex },
        { 'profile.headline': regex },
      ],
    })
      .select('username displayName profile linkedAccounts createdAt updatedAt')
      .sort({ updatedAt: -1, _id: -1 })
      .limit(12)
      .lean();

    return res.json({
      message: 'Search loaded.',
      results: users.map((user) => buildPublicProfilePayload(user)),
    });
  } catch (err) {
    console.error('Public profile search error:', err);
    return res.status(500).json({ message: 'Failed to search public profiles.' });
  }
};

exports.getPublicProfile = async (req, res) => {
  const username = normalizeUsername(req.params?.username);

  try {
    if (!username) {
      return res.status(404).json({ message: 'Profile not found.' });
    }

    const user = await User.findOne({
      username,
      'preferences.profilePublic': true,
    })
      .select('username displayName profile linkedAccounts createdAt updatedAt')
      .lean();

    if (!user) {
      return res.status(404).json({ message: 'Profile not found.' });
    }

    return res.json({
      message: 'Profile loaded.',
      profile: buildPublicProfilePayload(user),
    });
  } catch (err) {
    console.error('Get public profile error:', err);
    return res.status(500).json({ message: 'Failed to load public profile.' });
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
    const session = await resolveRefreshSessionFromCookie(req, res);
    if (!session?.user || session.replayDetected) {
      clearRefreshCookie(res, req);
      return res.status(200).json({ authenticated: false, message: 'No active refresh session.' });
    }

    let tokenPair;
    if (session.tokenState === 'grace') {
      tokenPair = reissueCurrentRefreshSession(session.user, req, session.sid, session.session);
    } else if (session.sid) {
      tokenPair = rotateRefreshSessionToken(session.user, req, session.sid, session.session);
    } else {
      tokenPair = createTrackedRefreshSession(session.user, req);
    }

    await session.user.save();

    res.cookie('refreshToken', tokenPair.refreshToken, buildCookieOptions(req));

    return res.json({
      message: 'Session refreshed.',
      token: tokenPair.accessToken,
      accessToken: tokenPair.accessToken,
      userId: toObjectIdString(session.user._id),
      continentalId: toObjectIdString(session.user._id),
    });
  } catch (err) {
    console.error('Refresh token error:', err);
    clearRefreshCookie(res, req);
    return res.status(200).json({ authenticated: false, message: 'Invalid refresh session.' });
  }
};

exports.updateProfile = async (req, res) => {
  const incoming = req.body || {};
  const currentPassword = req.body?.currentPassword || '';

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    let verification = null;
    let emailChanged = false;

    if (hasOwn(incoming, 'username')) {
      if (!normalizeUsername(incoming.username)) {
        return res.status(400).json({ message: USERNAME_VALIDATION_MESSAGE });
      }
      await applyUsernameChange(user, incoming.username);
    }

    if (hasOwn(incoming, 'displayName')) {
      const displayName = sanitizeText(incoming.displayName, 60);
      if (displayName.length < 2) {
        return res.status(400).json({ message: 'Display name must be at least 2 characters.' });
      }
      user.displayName = displayName;
    }

    if (hasOwn(incoming, 'email')) {
      emailChanged = await applyEmailChange(user, incoming.email, currentPassword);
      if (emailChanged) {
        verification = prepareEmailVerification(user);
      }
    }

    user.profile = normalizeProfile(incoming, user.profile || {});
    appendAuditEvent(
      user,
      req,
      'profile_updated',
      emailChanged ? 'Profile updated and email changed.' : 'Profile updated.',
      { emailChanged }
    );
    await user.save();

    const verificationDelivery = verification
      ? await sendVerificationEmail(user, req, verification)
      : null;

    if (emailChanged) {
      await sendSecurityAlertEmail(
        user,
        'Your Continental ID email was changed',
        'Email change detected',
        'Your account email was updated and now requires verification.',
        [
          `Time: ${new Date().toUTCString()}`,
          `IP address: ${parseClientIp(req) || 'Unknown'}`,
        ]
      );
    }

    const message = verification
      ? getVerificationDeliveryMessage(
          'Profile updated. Please verify your new email address.',
          'Profile updated, but the verification email could not be sent right now.',
          verificationDelivery
        )
      : 'Profile updated.';

    return sendUserResponse(res, 200, message, user, {
      verificationEmail: verification ? serializeVerificationDelivery(verificationDelivery) : undefined,
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    if (isDuplicateKeyError(err)) {
      return res.status(409).json({ message: getDuplicateUserFieldMessage(err) });
    }
    console.error('Update profile error:', err);
    return res.status(500).json({ message: 'Failed to update profile.' });
  }
};

exports.updateEmail = async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const currentPassword = req.body?.currentPassword || '';

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const emailChanged = await applyEmailChange(user, email, currentPassword);
    let verification = null;
    if (emailChanged) {
      verification = prepareEmailVerification(user);
    }

    appendAuditEvent(
      user,
      req,
      'email_updated',
      emailChanged ? 'Email updated.' : 'Email update checked.',
      { emailChanged }
    );
    await user.save();

    const verificationDelivery = verification
      ? await sendVerificationEmail(user, req, verification)
      : null;

    if (emailChanged) {
      await sendSecurityAlertEmail(
        user,
        'Your Continental ID email was changed',
        'Email change detected',
        'Your Continental ID email was changed and needs to be verified again.',
        [
          `Time: ${new Date().toUTCString()}`,
          `IP address: ${parseClientIp(req) || 'Unknown'}`,
        ]
      );
    }

    const message = verification
      ? getVerificationDeliveryMessage(
          'Email updated. Please verify your new email address.',
          'Email updated, but the verification email could not be sent right now.',
          verificationDelivery
        )
      : 'Email updated.';

    return sendUserResponse(res, 200, message, user, {
      verificationEmail: verification ? serializeVerificationDelivery(verificationDelivery) : undefined,
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    if (isDuplicateKeyError(err)) {
      return res.status(409).json({ message: getDuplicateUserFieldMessage(err) });
    }
    console.error('Update email error:', err);
    return res.status(500).json({ message: 'Failed to update email.' });
  }
};

exports.resendVerificationEmail = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: 'Email is already verified.' });
    }

    const verification = prepareEmailVerification(user);
    appendAuditEvent(user, req, 'verification_resent', 'Verification email resent.');
    await user.save();

    const verificationDelivery = await sendVerificationEmail(user, req, verification);
    const message = getVerificationDeliveryMessage(
      'Verification email sent.',
      'Verification email could not be sent right now.',
      verificationDelivery
    );

    return sendUserResponse(res, 200, message, user, {
      verificationEmail: serializeVerificationDelivery(verificationDelivery),
    });
  } catch (err) {
    console.error('Resend verification email error:', err);
    return res.status(500).json({ message: 'Failed to resend verification email.' });
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
    appendAuditEvent(user, req, 'preferences_updated', 'Preferences updated.');
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
    appendAuditEvent(user, req, 'linked_accounts_updated', 'External profiles updated.');
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
      auditEvents: payload.auditEvents,
      lastLoginAt: payload.lastLoginAt,
      lastLoginIp: payload.lastLoginIp,
      summary: payload.activitySummary,
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

    if (typeof req.body?.loginAlerts === 'boolean') {
      user.security.loginAlerts = req.body.loginAlerts;
    }

    appendAuditEvent(user, req, 'security_updated', 'Security settings updated.');
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
    const knownDeviceMap = getKnownDeviceMap(user);
    const sessions = Array.isArray(user.refreshSessions)
      ? [...user.refreshSessions]
          .map((session) =>
            serializeSession(
              session,
              currentSid,
              knownDeviceMap.get(sanitizeText(session?.deviceFingerprint, 128)) || null
            )
          )
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

    const currentSid = sanitizeText(req.user?.sid, 120);
    const revokedCurrentSession = targetSid === currentSid;
    appendAuditEvent(
      user,
      req,
      'session_revoked',
      revokedCurrentSession ? 'Current session revoked.' : 'Session revoked.',
      { currentSession: revokedCurrentSession }
    );
    await user.save();

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

    appendAuditEvent(
      user,
      req,
      'sessions_revoked',
      exceptCurrent ? 'All other sessions were revoked.' : 'All sessions were revoked.',
      { exceptCurrent }
    );
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
    clearPasswordReset(user);
    user.refreshTokenVersion += 1;
    user.refreshSessions = [];
    appendAuditEvent(user, req, 'password_updated', 'Password updated.');
    await user.save();

    await sendSecurityAlertEmail(
      user,
      'Your Continental ID password was changed',
      'Password changed',
      'Your Continental ID password was updated.',
      [
        `Time: ${new Date().toUTCString()}`,
        `IP address: ${parseClientIp(req) || 'Unknown'}`,
      ]
    );

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
    const knownDeviceMap = getKnownDeviceMap(user);
    const sessions = Array.isArray(user.refreshSessions)
      ? user.refreshSessions.map((session) =>
          serializeSession(
            session,
            req.user?.sid,
            knownDeviceMap.get(sanitizeText(session?.deviceFingerprint, 128)) || null
          )
        )
      : [];

    appendAuditEvent(user, req, 'account_exported', 'Account export generated.');
    await user.save();

    return res.json({
      message: 'Account export generated.',
      exportedAt: new Date().toISOString(),
      data: {
        account: payload,
        sessions,
        activitySummary: buildActivitySummary(
          Array.isArray(user.recentLogins) ? user.recentLogins : [],
          Array.isArray(user.loginDayCounts) ? user.loginDayCounts : []
        ),
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

    await sendSecurityAlertEmail(
      user,
      'Your Continental ID account was deleted',
      'Account deleted',
      'Your Continental ID account was permanently deleted.',
      [`Time: ${new Date().toUTCString()}`]
    );

    await User.deleteOne({ _id: req.user.id });
    clearRefreshCookie(res, req);

    return res.json({ message: 'Account deleted permanently.' });
  } catch (err) {
    console.error('Delete account error:', err);
    return res.status(500).json({ message: 'Failed to delete account.' });
  }
};
