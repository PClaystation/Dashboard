const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const ApiRateLimitBucket = require('../models/ApiRateLimitBucket');
const LoginThrottle = require('../models/LoginThrottle');
const User = require('../models/User');
const sendEmail = require('../utils/email');
const { createEmailVerificationToken } = require('../utils/emailVerification');
const {
  buildOtpAuthUrl,
  generateBackupCodes,
  generateMfaSecret,
  verifyTotp,
} = require('../utils/mfa');
const {
  DISPLAY_NAME_MODERATION_MESSAGE,
  USERNAME_VALIDATION_MESSAGE,
  USERNAME_MODERATION_MESSAGE,
  containsBlockedNameTerm,
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
const PASSWORD_RESET_EMAIL_COOLDOWN_MS =
  Number(process.env.PASSWORD_RESET_EMAIL_COOLDOWN_MS) || 10 * 60 * 1000;
const VERIFICATION_EMAIL_COOLDOWN_MS =
  Number(process.env.VERIFICATION_EMAIL_COOLDOWN_MS) || 30 * 60 * 1000;
const EMAIL_DAILY_LIMIT = Number(process.env.EMAIL_DAILY_LIMIT) || 100;
const EMAIL_MONTHLY_LIMIT = Number(process.env.EMAIL_MONTHLY_LIMIT) || 3000;
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
const DEFAULT_PUBLIC_PROFILE = {
  headline: true,
  role: true,
  organization: true,
  bio: true,
  currentFocus: true,
  focusAreas: true,
  pronouns: false,
  location: true,
  website: true,
  timezone: false,
  language: false,
  linkedAccounts: false,
  memberSince: true,
};

const DEFAULT_DASHBOARD_ORIGIN = 'https://dashboard.continental-hub.com';
const DEFAULT_LOGIN_ORIGIN = 'https://login.continental-hub.com';
const DEFAULT_LOGIN_POPUP_URL = `${DEFAULT_LOGIN_ORIGIN}/popup.html`;
const DEFAULT_EMAIL_VERIFY_PATH = '/verify.html';
const DEFAULT_PASSWORD_RESET_PATH = '/reset-password.html';
const EMAIL_VERIFICATION_SUBJECT = 'Verify your Continental ID email';
const PASSWORD_RESET_SUBJECT = 'Reset your Continental ID password';
const AVATAR_DATA_URL_MAX_LENGTH = 350000;
const AVATAR_DATA_URL_PATTERN = /^data:image\/(?:png|jpe?g|gif|webp);base64,[a-z0-9+/=]+$/i;
const MFA_BACKUP_CODE_COUNT = 8;
const MAX_FOCUS_AREAS = 8;

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj || {}, key);

const toObjectIdString = (value) => String(value || '');
const normalizeEmail = (email) => String(email || '').trim().toLowerCase();
const normalizeLoginIdentifier = (value) => String(value || '').trim().toLowerCase();
const sanitizeText = (value, maxLength = 120) => String(value || '').trim().slice(0, maxLength);
const hashToken = (value) => crypto.createHash('sha256').update(String(value || '')).digest('hex');

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const sanitizeDisplayName = (displayName, email = '') => {
  const cleaned = sanitizeText(displayName, 60);
  if (cleaned.length >= 2 && !containsBlockedNameTerm(cleaned)) return cleaned;

  const fallback = sanitizeText(String(email).split('@')[0], 60);
  if (fallback && !containsBlockedNameTerm(fallback)) return fallback;

  return 'User';
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

const isHostedLoginOrigin = (value) => {
  const resolved = resolveAbsoluteUrl(value);
  if (!resolved) return false;

  try {
    const origin = new URL(resolved).origin;
    return origin === DEFAULT_DASHBOARD_ORIGIN || origin === DEFAULT_LOGIN_ORIGIN;
  } catch {
    return false;
  }
};

const resolveLoginPopupPageUrl = (req) => {
  const explicitLoginPopupUrl = resolveAbsoluteUrl(
    process.env.LOGIN_POPUP_URL || process.env.PUBLIC_LOGIN_POPUP_URL || process.env.PUBLIC_LOGIN_URL
  );
  if (explicitLoginPopupUrl) {
    return explicitLoginPopupUrl;
  }

  const appBaseUrl = resolveAbsoluteUrl(
    process.env.APP_BASE_URL || process.env.PUBLIC_APP_URL || process.env.PUBLIC_BASE_URL
  );
  if (isHostedLoginOrigin(appBaseUrl)) {
    return DEFAULT_LOGIN_POPUP_URL;
  }

  if ((process.env.NODE_ENV || 'development') !== 'production') {
    const requestOrigin = getRequestOrigin(req);
    if (isHostedLoginOrigin(requestOrigin)) {
      return DEFAULT_LOGIN_POPUP_URL;
    }
  }

  return '';
};

const getUtcDayWindowStart = (value = Date.now()) => {
  const date = new Date(value);
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
};

const getUtcMonthWindowStart = (value = Date.now()) => {
  const date = new Date(value);
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1));
};

const addUtcDays = (value, days) => {
  const date = new Date(value);
  date.setUTCDate(date.getUTCDate() + days);
  return date;
};

const addUtcMonths = (value, months) => {
  const date = new Date(value);
  date.setUTCMonth(date.getUTCMonth() + months);
  return date;
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

  const loginPopupUrl = resolveLoginPopupPageUrl(req);
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

const hasPendingEmailVerification = (user) =>
  Boolean(
    sanitizeText(user?.verificationToken, 160) &&
      user?.verificationTokenExpires &&
      new Date(user.verificationTokenExpires).getTime() > Date.now()
  );

const getVerificationEmailCooldownRemainingMs = (user) => {
  const sentAt = new Date(user?.emailDelivery?.verificationLastSentAt || 0).getTime();
  if (!sentAt) return 0;
  return Math.max(0, sentAt + VERIFICATION_EMAIL_COOLDOWN_MS - Date.now());
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
  user.passwordResetRequestedAt = new Date();
  return reset;
};

const clearPasswordReset = (user) => {
  if (!user) return;
  user.passwordResetToken = '';
  user.passwordResetTokenExpires = null;
};

const formatEmailDate = (value) => new Date(value).toUTCString();

const renderEmailParagraphs = (paragraphs = [], styles = {}) => {
  const mergedStyles = {
    margin: '0 0 14px 0',
    fontFamily: "'Helvetica Neue',Arial,sans-serif",
    fontSize: '16px',
    lineHeight: '1.75',
    color: '#1f2937',
    ...styles,
  };
  const styleAttr = Object.entries(mergedStyles)
    .map(([key, value]) => `${key}:${value};`)
    .join('');

  return paragraphs
    .filter(Boolean)
    .map((paragraph, index, array) => {
      const marginStyle =
        index === array.length - 1
          ? styleAttr.replace('margin:0 0 14px 0;', 'margin:0;')
          : styleAttr;
      return `<p style="${marginStyle}">${paragraph}</p>`;
    })
    .join('');
};

const renderEmailBulletList = (items = [], accentColor = '#0f766e') => {
  const normalizedItems = items.filter(Boolean);
  if (!normalizedItems.length) return '';

  return `
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin:0;">
      ${normalizedItems
        .map(
          (item) => `
            <tr>
              <td valign="top" style="width:28px;padding:0 0 12px 0;">
                <table role="presentation" cellpadding="0" cellspacing="0" style="margin:2px 0 0 0;">
                  <tr>
                    <td style="width:12px;height:12px;border-radius:999px;background-color:${accentColor};font-size:0;line-height:0;">&nbsp;</td>
                  </tr>
                </table>
              </td>
              <td style="padding:0 0 12px 0;font-family:'Helvetica Neue',Arial,sans-serif;font-size:15px;line-height:1.7;color:#334155;">
                ${item}
              </td>
            </tr>
          `
        )
        .join('')}
    </table>
  `;
};

const renderEmailDetailRows = (rows = []) => {
  const normalizedRows = rows.filter((row) => row?.label && row?.value);
  if (!normalizedRows.length) return '';

  return normalizedRows
    .map(
      (row, index) => `
        <tr>
          <td style="padding:${index === 0 ? '0' : '14px'} 0 0 0;border-top:${index === 0 ? '0' : '1px solid #dbe4ea'};">
            <p style="margin:0 0 4px 0;font-family:'Helvetica Neue',Arial,sans-serif;font-size:11px;line-height:1.4;letter-spacing:0.16em;text-transform:uppercase;color:#64748b;font-weight:700;">
              ${row.label}
            </p>
            <p style="margin:0;font-family:'Helvetica Neue',Arial,sans-serif;font-size:15px;line-height:1.7;color:#0f172a;">
              ${row.value}
            </p>
          </td>
        </tr>
      `
    )
    .join('');
};

const buildBrandedEmailHtml = ({
  preheader = '',
  accentColor = '#0f766e',
  accentSoft = '#dff6f1',
  accentStrong = '#0b5d56',
  surfaceTint = '#f8fbfc',
  panelBorder = '#dbe4ea',
  eyebrow = 'Continental ID',
  title = '',
  lead = '',
  greeting = '',
  bodyParagraphs = [],
  ctaLabel = '',
  ctaUrl = '',
  detailTitle = '',
  detailRows = [],
  bulletTitle = '',
  bulletItems = [],
  fallbackLabel = '',
  footerNote = '',
}) => {
  const safePreheader = escapeHtml(preheader);
  const safeEyebrow = escapeHtml(eyebrow);
  const safeTitle = escapeHtml(title);
  const safeLead = escapeHtml(lead);
  const safeGreeting = greeting;
  const safeCtaLabel = escapeHtml(ctaLabel);
  const safeCtaUrl = escapeHtml(ctaUrl);
  const safeDetailTitle = escapeHtml(detailTitle);
  const safeBulletTitle = escapeHtml(bulletTitle);
  const safeFallbackLabel = escapeHtml(fallbackLabel);
  const safeFooterNote = escapeHtml(footerNote);

  return `
    <div style="display:none;max-height:0;max-width:0;overflow:hidden;opacity:0;color:transparent;">
      ${safePreheader}
    </div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin:0;padding:32px 12px;background-color:#efe7dc;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:680px;margin:0 auto;">
            <tr>
              <td style="padding:0 0 16px 0;text-align:center;">
                <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto;">
                  <tr>
                    <td style="padding:8px 14px;border-radius:999px;background-color:${accentSoft};border:1px solid ${panelBorder};font-family:'Helvetica Neue',Arial,sans-serif;font-size:11px;line-height:1.2;letter-spacing:0.18em;text-transform:uppercase;color:${accentStrong};font-weight:700;">
                      ${safeEyebrow}
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td style="padding:0;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background-color:#15202b;border-radius:30px 30px 0 0;">
                  <tr>
                    <td style="padding:12px 28px 0 28px;">
                      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;">
                        <tr>
                          <td style="height:6px;border-radius:999px;background-color:${accentColor};font-size:0;line-height:0;">&nbsp;</td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:28px 28px 26px 28px;">
                      <p style="margin:0 0 14px 0;font-family:Georgia,'Times New Roman',serif;font-size:36px;line-height:1.08;color:#ffffff;font-weight:700;">
                        ${safeTitle}
                      </p>
                      <p style="margin:0;font-family:'Helvetica Neue',Arial,sans-serif;font-size:17px;line-height:1.75;color:#dbe7ef;">
                        ${safeLead}
                      </p>
                    </td>
                  </tr>
                </table>
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background-color:#ffffff;border:1px solid ${panelBorder};border-top:0;border-radius:0 0 30px 30px;">
                  <tr>
                    <td style="padding:30px 28px 28px 28px;">
                      ${renderEmailParagraphs([safeGreeting], {
                        margin: '0 0 16px 0',
                        fontSize: '16px',
                        lineHeight: '1.75',
                        color: '#0f172a',
                      })}
                      ${renderEmailParagraphs(bodyParagraphs)}
                      ${
                        safeCtaLabel && safeCtaUrl
                          ? `
                            <table role="presentation" cellpadding="0" cellspacing="0" style="margin:26px 0 24px 0;">
                              <tr>
                                <td style="border-radius:999px;background-color:${accentColor};">
                                  <a href="${safeCtaUrl}" style="display:inline-block;padding:15px 26px;font-family:'Helvetica Neue',Arial,sans-serif;font-size:15px;line-height:1.2;font-weight:700;color:#ffffff;text-decoration:none;">
                                    ${safeCtaLabel}
                                  </a>
                                </td>
                              </tr>
                            </table>
                          `
                          : ''
                      }
                      ${
                        safeDetailTitle && detailRows.length
                          ? `
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin:0 0 22px 0;background-color:${surfaceTint};border:1px solid ${panelBorder};border-radius:22px;">
                              <tr>
                                <td style="padding:20px 20px 18px 20px;">
                                  <p style="margin:0 0 14px 0;font-family:'Helvetica Neue',Arial,sans-serif;font-size:12px;line-height:1.4;letter-spacing:0.14em;text-transform:uppercase;color:${accentStrong};font-weight:700;">
                                    ${safeDetailTitle}
                                  </p>
                                  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;">
                                    ${renderEmailDetailRows(detailRows)}
                                  </table>
                                </td>
                              </tr>
                            </table>
                          `
                          : ''
                      }
                      ${
                        safeBulletTitle && bulletItems.length
                          ? `
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin:0 0 22px 0;background-color:#ffffff;border:1px solid ${panelBorder};border-radius:22px;">
                              <tr>
                                <td style="padding:20px;">
                                  <p style="margin:0 0 14px 0;font-family:'Helvetica Neue',Arial,sans-serif;font-size:12px;line-height:1.4;letter-spacing:0.14em;text-transform:uppercase;color:#475569;font-weight:700;">
                                    ${safeBulletTitle}
                                  </p>
                                  ${renderEmailBulletList(bulletItems, accentColor)}
                                </td>
                              </tr>
                            </table>
                          `
                          : ''
                      }
                      ${
                        safeFallbackLabel && safeCtaUrl
                          ? `
                            <p style="margin:0 0 10px 0;font-family:'Helvetica Neue',Arial,sans-serif;font-size:14px;line-height:1.7;color:#475569;">
                              ${safeFallbackLabel}
                            </p>
                            <p style="margin:0;font-family:'Helvetica Neue',Arial,sans-serif;font-size:14px;line-height:1.8;word-break:break-all;">
                              <a href="${safeCtaUrl}" style="color:${accentStrong};text-decoration:underline;">
                                ${safeCtaUrl}
                              </a>
                            </p>
                          `
                          : ''
                      }
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td style="padding:18px 20px 0 20px;text-align:center;font-family:'Helvetica Neue',Arial,sans-serif;font-size:12px;line-height:1.8;color:#6b7280;">
                ${safeFooterNote}
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  `;
};

const buildVerificationEmailContent = (user, verificationUrl, expiresAt) => {
  const displayName = sanitizeText(user?.displayName || user?.email, 60) || 'there';
  const emailAddress = sanitizeText(user?.email, 160);
  const expiresLabel = formatEmailDate(expiresAt);
  const safeDisplayName = escapeHtml(displayName);
  const safeEmailAddress = escapeHtml(emailAddress);
  const verificationTarget = emailAddress
    ? `the email address ${emailAddress}`
    : 'your email address';
  const safeVerificationTarget = safeEmailAddress
    ? `the email address <strong>${safeEmailAddress}</strong>`
    : 'your email address';

  return {
    subject: EMAIL_VERIFICATION_SUBJECT,
    text: [
      `Hi ${displayName},`,
      '',
      `Verify ${verificationTarget} on your Continental ID account by opening this link:`,
      verificationUrl,
      '',
      `This link expires on ${expiresLabel}.`,
      'If you did not create this account, you can ignore this message.',
    ].join('\n'),
    html: buildBrandedEmailHtml({
      preheader: 'Verify your Continental ID email to finish setting up your account.',
      accentColor: '#0f766e',
      accentSoft: '#dff6f1',
      accentStrong: '#0b5d56',
      surfaceTint: '#f3fbf8',
      panelBorder: '#d7e5e1',
      title: 'Verify your email',
      lead: 'Finish setting up your account and keep sign-in trusted across the dashboard.',
      greeting: `Hi ${safeDisplayName},`,
      bodyParagraphs: [
        `We received a request to verify ${safeVerificationTarget} for your Continental ID account.`,
        'Use the button below to confirm the address and unlock verified sign-in.',
      ],
      ctaLabel: 'Verify email address',
      ctaUrl: verificationUrl,
      detailTitle: 'Verification details',
      detailRows: [
        { label: 'Address', value: safeEmailAddress || 'Your email address' },
        { label: 'Link expires', value: escapeHtml(expiresLabel) },
      ],
      bulletTitle: 'What happens next',
      bulletItems: [
        'Your email address is marked as verified for this account.',
        'You can complete sign-in flows that require email verification.',
        'If this was not your account creation attempt, no action is required.',
      ],
      fallbackLabel: 'If the button does not work, copy and paste this link into your browser:',
      footerNote: 'This verification link was sent for Continental ID account setup.',
    }),
  };
};

const resolvePasswordResetPageUrl = (req) => {
  const explicitResetUrl = resolveAbsoluteUrl(
    process.env.PASSWORD_RESET_URL || process.env.PASSWORD_RESET_PAGE_URL
  );
  if (explicitResetUrl) {
    return explicitResetUrl;
  }

  const loginPopupUrl = resolveLoginPopupPageUrl(req);
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
  const expiresLabel = formatEmailDate(expiresAt);
  const safeDisplayName = escapeHtml(displayName);

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
    html: buildBrandedEmailHtml({
      preheader: 'Use this secure link to reset your Continental ID password.',
      accentColor: '#b45309',
      accentSoft: '#fff1dd',
      accentStrong: '#92400e',
      surfaceTint: '#fff8ee',
      panelBorder: '#eadfce',
      title: 'Reset your password',
      lead: 'A password reset was requested for your Continental ID account.',
      greeting: `Hi ${safeDisplayName},`,
      bodyParagraphs: [
        'Use the secure link below to choose a new password and restore access to your account.',
        'For security, this reset link works only for a limited time.',
      ],
      ctaLabel: 'Reset password',
      ctaUrl: resetUrl,
      detailTitle: 'Reset details',
      detailRows: [
        { label: 'Link expires', value: escapeHtml(expiresLabel) },
        { label: 'Requested for', value: 'Your Continental ID account' },
      ],
      bulletTitle: 'Security notes',
      bulletItems: [
        'After resetting, use the new password the next time you sign in.',
        'If you did not request this reset, you can ignore this email.',
        'If you keep receiving unexpected reset emails, review your account security.',
      ],
      fallbackLabel: 'If the button does not work, copy and paste this link into your browser:',
      footerNote: 'This password reset email was sent because a reset request was submitted for your account.',
    }),
  };
};

const serializeVerificationDelivery = (delivery) => {
  const payload = {
    sent: Boolean(delivery?.sent),
  };

  const reason = sanitizeText(delivery?.reason, 60);
  if (reason) {
    payload.reason = reason;
  }

  return payload;
};

const getVerificationDeliveryMessage = (
  successMessage,
  cooldownMessage,
  failureMessage,
  delivery
) => {
  if (delivery?.sent) {
    return successMessage;
  }

  if (delivery?.reason === 'cooldown') {
    return cooldownMessage;
  }

  return failureMessage;
};

const reserveEmailQuotaWindow = async ({ key, windowStart, expiresAt, limit, amount = 1 }) => {
  const normalizedAmount = Math.max(1, Math.trunc(Number(amount || 1)));
  const maxAllowedCount = limit - normalizedAmount;

  if (maxAllowedCount < 0) {
    return false;
  }

  const entry = await ApiRateLimitBucket.findOneAndUpdate(
    {
      key,
      windowStart,
      count: { $lte: maxAllowedCount },
    },
    {
      $setOnInsert: {
        expiresAt,
      },
      $inc: {
        count: normalizedAmount,
      },
    },
    {
      upsert: true,
      new: true,
    }
  ).lean();

  return Boolean(entry);
};

const rollbackEmailQuotaWindow = async ({ key, windowStart, amount = 1 }) => {
  const normalizedAmount = Math.max(1, Math.trunc(Number(amount || 1)));
  await ApiRateLimitBucket.updateOne(
    { key, windowStart },
    {
      $inc: {
        count: -normalizedAmount,
      },
    }
  );
};

const reserveEmailQuota = async (recipientCount = 1) => {
  const amount = Math.max(1, Math.trunc(Number(recipientCount || 1)));
  const now = Date.now();
  const dayWindowStart = getUtcDayWindowStart(now);
  const monthWindowStart = getUtcMonthWindowStart(now);
  const dayKey = 'outbound-email:global:day';
  const monthKey = 'outbound-email:global:month';

  const reservedDay = await reserveEmailQuotaWindow({
    key: dayKey,
    windowStart: dayWindowStart,
    expiresAt: addUtcDays(dayWindowStart, 2),
    limit: EMAIL_DAILY_LIMIT,
    amount,
  });

  if (!reservedDay) {
    return { ok: false, reason: 'quota_daily_limit' };
  }

  const reservedMonth = await reserveEmailQuotaWindow({
    key: monthKey,
    windowStart: monthWindowStart,
    expiresAt: addUtcMonths(monthWindowStart, 2),
    limit: EMAIL_MONTHLY_LIMIT,
    amount,
  });

  if (!reservedMonth) {
    await rollbackEmailQuotaWindow({
      key: dayKey,
      windowStart: dayWindowStart,
      amount,
    });
    return { ok: false, reason: 'quota_monthly_limit' };
  }

  return {
    ok: true,
    reservation: {
      amount,
      dayKey,
      dayWindowStart,
      monthKey,
      monthWindowStart,
    },
  };
};

const deliverManagedEmail = async ({
  user = null,
  to,
  subject,
  text,
  html,
  onSent = null,
} = {}) => {
  const recipients = (Array.isArray(to) ? to : [to]).filter(Boolean);
  if (recipients.length === 0) {
    return { sent: false, reason: 'missing_recipient' };
  }

  const quota = await reserveEmailQuota(recipients.length);
  if (!quota.ok) {
    return { sent: false, reason: quota.reason };
  }

  const rollbackReservation = async () => {
    await rollbackEmailQuotaWindow({
      key: quota.reservation.dayKey,
      windowStart: quota.reservation.dayWindowStart,
      amount: quota.reservation.amount,
    });
    await rollbackEmailQuotaWindow({
      key: quota.reservation.monthKey,
      windowStart: quota.reservation.monthWindowStart,
      amount: quota.reservation.amount,
    });
  };

  let response = null;
  try {
    response = await sendEmail({
      to: recipients,
      subject,
      text,
      html,
    });

    if (response?.skipped) {
      await rollbackReservation();
      return {
        sent: false,
        reason: sanitizeText(response.reason, 60) || 'email_skipped',
      };
    }
  } catch (err) {
    await rollbackReservation();
    console.error('Managed email delivery error:', err);
    return { sent: false, reason: 'delivery_error' };
  }

  try {
    if (typeof onSent === 'function') {
      onSent();
    }

    if (user?.isModified && user.isModified()) {
      await user.save();
    }
  } catch (err) {
    console.error('Email post-send persistence error:', err);
  }

  return {
    sent: true,
    id: sanitizeText(response?.id, 120),
  };
};

const sendVerificationEmail = async (user, req, verification) => {
  if (!user?.email || !verification?.token) {
    return { sent: false };
  }

  const verificationUrl = buildEmailVerificationUrl(req, verification.token);
  if (!verificationUrl) {
    console.warn('Verification email URL is not configured; skipping verification email.');
    return { sent: false, reason: 'url_not_configured' };
  }

  const emailContent = buildVerificationEmailContent(user, verificationUrl, verification.expiresAt);
  return deliverManagedEmail({
    user,
    to: user.email,
    subject: emailContent.subject,
    text: emailContent.text,
    html: emailContent.html,
    onSent: () => {
      user.emailDelivery = user.emailDelivery || {};
      user.emailDelivery.verificationLastSentAt = new Date();
    },
  });
};

const sendPasswordResetEmail = async (user, req, reset) => {
  if (!user?.email || !reset?.token) {
    return { sent: false };
  }

  const resetUrl = buildPasswordResetUrl(req, reset.token);
  if (!resetUrl) {
    console.warn('Password reset URL is not configured; skipping password reset email.');
    return { sent: false, reason: 'url_not_configured' };
  }

  const emailContent = buildPasswordResetEmailContent(user, resetUrl, reset.expiresAt);
  return deliverManagedEmail({
    to: user.email,
    subject: emailContent.subject,
    text: emailContent.text,
    html: emailContent.html,
  });
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
    html: buildBrandedEmailHtml({
      preheader: title || 'Security alert for your Continental ID account.',
      accentColor: '#b91c1c',
      accentSoft: '#fee2e2',
      accentStrong: '#991b1b',
      surfaceTint: '#fff5f5',
      panelBorder: '#f1d3d3',
      title: title || 'Security alert',
      lead: 'A security-sensitive action was detected on your Continental ID account.',
      greeting: 'Security notice,',
      bodyParagraphs: [safeIntro],
      detailTitle: normalizedDetails.length ? 'Event details' : '',
      detailRows: normalizedDetails.map((item, index) => ({
        label: `Detail ${index + 1}`,
        value: escapeHtml(item),
      })),
      bulletTitle: 'Recommended next steps',
      bulletItems: [
        'Review the activity details below and confirm that you recognize them.',
        'If this action was not expected, change your password immediately.',
        'Check recent sign-ins and revoke access on devices you do not recognize.',
      ],
      footerNote: 'This alert was sent because security notifications are enabled for your Continental ID account.',
    }),
  };
};

const shouldSendSecurityNotifications = (user, emailOverride = '') =>
  Boolean(
    sanitizeText(emailOverride || user?.email, 320) &&
      (hasOwn(user?.preferences?.notifications || {}, 'security')
        ? user?.preferences?.notifications?.security
        : DEFAULT_NOTIFICATIONS.security)
  );

const shouldSendLoginAlert = (user) =>
  shouldSendSecurityNotifications(user) &&
  Boolean(hasOwn(user?.security || {}, 'loginAlerts') ? user?.security?.loginAlerts : true);

const sendSecurityAlertEmail = async (user, subject, title, intro, details = [], options = {}) => {
  const recipient = sanitizeText(options.emailOverride || user?.email, 320);
  if (!shouldSendSecurityNotifications(user, recipient)) {
    return { sent: false };
  }

  const emailContent = buildSecurityEmailContent({ title, intro, details });
  return deliverManagedEmail({
    to: recipient,
    subject,
    text: emailContent.text,
    html: emailContent.html,
  });
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
    trusted: false,
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
      trusted: Boolean(currentDevice?.trusted),
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

const normalizePublicProfilePreferences = (incoming = {}, current = DEFAULT_PUBLIC_PROFILE) => {
  const source = current || DEFAULT_PUBLIC_PROFILE;

  return {
    headline: hasOwn(incoming, 'headline') ? Boolean(incoming.headline) : Boolean(source.headline),
    role: hasOwn(incoming, 'role') ? Boolean(incoming.role) : Boolean(source.role),
    organization: hasOwn(incoming, 'organization')
      ? Boolean(incoming.organization)
      : Boolean(source.organization),
    bio: hasOwn(incoming, 'bio') ? Boolean(incoming.bio) : Boolean(source.bio),
    currentFocus: hasOwn(incoming, 'currentFocus')
      ? Boolean(incoming.currentFocus)
      : Boolean(source.currentFocus),
    focusAreas: hasOwn(incoming, 'focusAreas')
      ? Boolean(incoming.focusAreas)
      : Boolean(source.focusAreas),
    pronouns: hasOwn(incoming, 'pronouns') ? Boolean(incoming.pronouns) : Boolean(source.pronouns),
    location: hasOwn(incoming, 'location') ? Boolean(incoming.location) : Boolean(source.location),
    website: hasOwn(incoming, 'website') ? Boolean(incoming.website) : Boolean(source.website),
    timezone: hasOwn(incoming, 'timezone') ? Boolean(incoming.timezone) : Boolean(source.timezone),
    language: hasOwn(incoming, 'language') ? Boolean(incoming.language) : Boolean(source.language),
    linkedAccounts: hasOwn(incoming, 'linkedAccounts')
      ? Boolean(incoming.linkedAccounts)
      : Boolean(source.linkedAccounts),
    memberSince: hasOwn(incoming, 'memberSince') ? Boolean(incoming.memberSince) : Boolean(source.memberSince),
  };
};

const getMfaState = (user) => ({
  enabled: Boolean(user?.security?.mfa?.enabled),
  hasPendingSetup: Boolean(user?.security?.mfa?.pendingSecret),
  enrolledAt: user?.security?.mfa?.enrolledAt || null,
  lastUsedAt: user?.security?.mfa?.lastUsedAt || null,
  backupCodesRemaining: Array.isArray(user?.security?.mfa?.backupCodes) ? user.security.mfa.backupCodes.length : 0,
});

const sanitizeMfaCode = (value) => String(value || '').replace(/\s+/g, '').slice(0, 8);
const sanitizeBackupCode = (value) =>
  String(value || '')
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9-]/g, '')
    .slice(0, 24);

const hashBackupCodes = (codes = []) => codes.map((code) => hashToken(sanitizeBackupCode(code)));

const buildMfaSetupPayload = (user, secret, backupCodes) => ({
  secret,
  otpAuthUrl: buildOtpAuthUrl({
    secret,
    accountName: sanitizeText(user?.email || user?.username || user?._id, 120) || 'user',
  }),
  backupCodes,
});

const verifyBackupCode = (user, backupCode) => {
  const normalized = sanitizeBackupCode(backupCode);
  if (!normalized) {
    return { ok: false };
  }

  const hashedCandidate = hashToken(normalized);
  const storedCodes = Array.isArray(user?.security?.mfa?.backupCodes) ? user.security.mfa.backupCodes : [];
  const matchIndex = storedCodes.findIndex((value) => value === hashedCandidate);
  if (matchIndex < 0) {
    return { ok: false };
  }

  user.security.mfa.backupCodes.splice(matchIndex, 1);
  return { ok: true, usedBackupCode: normalized };
};

const verifyMfaAttempt = (user, { mfaCode = '', backupCode = '' } = {}) => {
  const secret = sanitizeText(user?.security?.mfa?.secret, 120);
  const normalizedCode = sanitizeMfaCode(mfaCode);

  if (normalizedCode && verifyTotp({ secret, token: normalizedCode })) {
    return { ok: true, method: 'totp' };
  }

  const backupResult = verifyBackupCode(user, backupCode);
  if (backupResult.ok) {
    return { ok: true, method: 'backup_code', usedBackupCode: backupResult.usedBackupCode };
  }

  return { ok: false };
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
const sanitizeRole = (value, fallback = '') => sanitizeText(value, 100) || fallback;
const sanitizeOrganization = (value, fallback = '') => sanitizeText(value, 100) || fallback;
const sanitizeCurrentFocus = (value, fallback = '') => sanitizeText(value, 160) || fallback;
const sanitizePronouns = (value, fallback = '') => sanitizeText(value, 40) || fallback;
const sanitizeFocusAreas = (value = []) => {
  const rawValues = Array.isArray(value) ? value : String(value || '').split(/[,\n]/);
  const next = [];
  const seen = new Set();

  for (const entry of rawValues) {
    const cleaned = sanitizeText(entry, 32);
    if (!cleaned) continue;

    const dedupeKey = cleaned.toLowerCase();
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    next.push(cleaned);

    if (next.length >= MAX_FOCUS_AREAS) {
      break;
    }
  }

  return next;
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
    avatar: hasOwn(incoming, 'avatar')
      ? sanitizeAvatar(incoming.avatar, sanitizeAvatar(currentProfile.avatar, ''))
      : sanitizeAvatar(currentProfile.avatar, ''),
    headline: hasOwn(incoming, 'headline')
      ? sanitizeHeadline(incoming.headline, '')
      : sanitizeHeadline(currentProfile.headline, ''),
    role: hasOwn(incoming, 'role')
      ? sanitizeRole(incoming.role, '')
      : sanitizeRole(currentProfile.role, ''),
    organization: hasOwn(incoming, 'organization')
      ? sanitizeOrganization(incoming.organization, '')
      : sanitizeOrganization(currentProfile.organization, ''),
    currentFocus: hasOwn(incoming, 'currentFocus')
      ? sanitizeCurrentFocus(incoming.currentFocus, '')
      : sanitizeCurrentFocus(currentProfile.currentFocus, ''),
    focusAreas: hasOwn(incoming, 'focusAreas')
      ? sanitizeFocusAreas(incoming.focusAreas)
      : sanitizeFocusAreas(currentProfile.focusAreas),
    pronouns: hasOwn(incoming, 'pronouns')
      ? sanitizePronouns(incoming.pronouns, '')
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
    publicProfile: normalizePublicProfilePreferences(
      incoming.publicProfile || {},
      source.publicProfile || DEFAULT_PUBLIC_PROFILE
    ),
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
    deviceTrusted: Boolean(knownDevice?.trusted),
    fingerprint: sanitizeText(session?.deviceFingerprint, 128),
    current: Boolean(sid && sid === sanitizeText(currentSid, 120)),
  };
};

const serializeDevice = (device, sessions = [], currentFingerprint = '') => {
  const fingerprint = sanitizeText(device?.fingerprint, 128);
  const relatedSessions = sessions.filter(
    (session) => sanitizeText(session?.deviceFingerprint, 128) === fingerprint
  );

  return {
    fingerprint,
    label: sanitizeText(device?.label, 60) || 'Browser device',
    trusted: Boolean(device?.trusted),
    firstSeenAt: device?.firstSeenAt || null,
    lastSeenAt: device?.lastSeenAt || null,
    lastIp: sanitizeText(device?.lastIp, 80),
    userAgent: sanitizeText(device?.userAgent, 300),
    activeSessions: relatedSessions.length,
    current: Boolean(fingerprint && fingerprint === sanitizeText(currentFingerprint, 128)),
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

  if (containsBlockedNameTerm(normalized)) {
    throw createHttpError(400, USERNAME_MODERATION_MESSAGE);
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
  const focusAreas = sanitizeFocusAreas(user?.profile?.focusAreas);
  const fields = [
    getDisplayableUsername(user),
    sanitizeText(user.displayName, 60),
    sanitizeText(user.email, 120),
    sanitizeAvatar(user.profile?.avatar, ''),
    sanitizeHeadline(user.profile?.headline, ''),
    sanitizeRole(user.profile?.role, '') || sanitizeOrganization(user.profile?.organization, ''),
    sanitizeText(user.profile?.bio, 320),
    sanitizeCurrentFocus(user.profile?.currentFocus, '') || (focusAreas.length ? 'focus-areas' : ''),
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
      role: sanitizeRole(user.profile?.role, ''),
      organization: sanitizeOrganization(user.profile?.organization, ''),
      currentFocus: sanitizeCurrentFocus(user.profile?.currentFocus, ''),
      focusAreas: sanitizeFocusAreas(user.profile?.focusAreas),
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
      publicProfile: normalizePublicProfilePreferences(
        user.preferences?.publicProfile || {},
        DEFAULT_PUBLIC_PROFILE
      ),
    },
    security: {
      loginAlerts: Boolean(hasOwn(user.security || {}, 'loginAlerts') ? user.security?.loginAlerts : true),
      passwordChangedAt: user.security?.passwordChangedAt || null,
      activeSessions: Array.isArray(user.refreshSessions) ? user.refreshSessions.length : 0,
      knownDevices: Array.isArray(user.knownDevices) ? user.knownDevices.length : 0,
      mfa: getMfaState(user),
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

const buildPublicProfilePayload = (user) => {
  const visibility = normalizePublicProfilePreferences(
    user?.preferences?.publicProfile || {},
    DEFAULT_PUBLIC_PROFILE
  );

  return {
    username: getDisplayableUsername(user),
    handle: `@${getDisplayableUsername(user)}`,
    displayName: sanitizeText(user?.displayName, 60) || 'User',
    createdAt: visibility.memberSince ? user?.createdAt || null : null,
    updatedAt: user?.updatedAt || null,
    profile: {
      avatar: sanitizeAvatar(user?.profile?.avatar, ''),
      headline: visibility.headline ? sanitizeHeadline(user?.profile?.headline, '') : '',
      role: visibility.role ? sanitizeRole(user?.profile?.role, '') : '',
      organization: visibility.organization ? sanitizeOrganization(user?.profile?.organization, '') : '',
      currentFocus: visibility.currentFocus ? sanitizeCurrentFocus(user?.profile?.currentFocus, '') : '',
      focusAreas: visibility.focusAreas ? sanitizeFocusAreas(user?.profile?.focusAreas) : [],
      pronouns: visibility.pronouns ? sanitizePronouns(user?.profile?.pronouns, '') : '',
      bio: visibility.bio ? sanitizeText(user?.profile?.bio, 320) : '',
      location: visibility.location ? sanitizeText(user?.profile?.location, 120) : '',
      website: visibility.website ? sanitizeText(user?.profile?.website, 240) : '',
      timezone: visibility.timezone ? sanitizeTimezone(user?.profile?.timezone, 'UTC') : '',
      language: visibility.language ? sanitizeLanguage(user?.profile?.language, 'en') : '',
    },
    linkedAccounts: visibility.linkedAccounts ? buildPublicLinkedAccounts(user?.linkedAccounts) : {},
  };
};

const buildPublicSearchFields = (user) => {
  const visibility = normalizePublicProfilePreferences(
    user?.preferences?.publicProfile || {},
    DEFAULT_PUBLIC_PROFILE
  );

  return {
    username: sanitizeText(getDisplayableUsername(user), 60).toLowerCase(),
    displayName: sanitizeText(user?.displayName, 60).toLowerCase(),
    headline: visibility.headline ? sanitizeHeadline(user?.profile?.headline, '').toLowerCase() : '',
    role: visibility.role ? sanitizeRole(user?.profile?.role, '').toLowerCase() : '',
    organization: visibility.organization ? sanitizeOrganization(user?.profile?.organization, '').toLowerCase() : '',
    currentFocus: visibility.currentFocus ? sanitizeCurrentFocus(user?.profile?.currentFocus, '').toLowerCase() : '',
    focusAreas: visibility.focusAreas
      ? sanitizeFocusAreas(user?.profile?.focusAreas).map((entry) => entry.toLowerCase())
      : [],
    bio: visibility.bio ? sanitizeText(user?.profile?.bio, 320).toLowerCase() : '',
    location: visibility.location ? sanitizeText(user?.profile?.location, 120).toLowerCase() : '',
    linkedAccounts: visibility.linkedAccounts
      ? Object.values(buildPublicLinkedAccounts(user?.linkedAccounts)).map((entry) =>
          sanitizeText(entry, 120).toLowerCase()
        )
      : [],
  };
};

const scoreTextField = (value, query, weights) => {
  const text = sanitizeText(value, 320).toLowerCase();
  if (!text || !query) return 0;
  if (text === query) return weights.exact;
  if (text.startsWith(query)) return weights.prefix;
  if (text.includes(query)) return weights.contains;
  return 0;
};

const scoreTextCollection = (values, query, weights) =>
  values.reduce((best, value) => Math.max(best, scoreTextField(value, query, weights)), 0);

const scorePublicProfileMatch = (user, rawQuery) => {
  const query = sanitizeText(rawQuery, 60).toLowerCase();
  if (query.length < 2) return 0;

  const fields = buildPublicSearchFields(user);

  let score = 0;
  score += scoreTextField(fields.username, query, { exact: 160, prefix: 110, contains: 78 });
  score += scoreTextField(fields.displayName, query, { exact: 120, prefix: 82, contains: 56 });
  score += scoreTextField(fields.role, query, { exact: 88, prefix: 62, contains: 42 });
  score += scoreTextField(fields.organization, query, { exact: 84, prefix: 58, contains: 40 });
  score += scoreTextField(fields.headline, query, { exact: 72, prefix: 48, contains: 34 });
  score += scoreTextField(fields.currentFocus, query, { exact: 68, prefix: 44, contains: 30 });
  score += scoreTextCollection(fields.focusAreas, query, { exact: 64, prefix: 40, contains: 28 });
  score += scoreTextField(fields.location, query, { exact: 32, prefix: 24, contains: 18 });
  score += scoreTextCollection(fields.linkedAccounts, query, { exact: 28, prefix: 20, contains: 16 });
  score += scoreTextField(fields.bio, query, { exact: 22, prefix: 16, contains: 12 });

  return score;
};

const buildPublicSearchQuery = (regex) => {
  const linkedClauses = LINKED_PROVIDERS.map((provider) => ({
    [`linkedAccounts.${provider}`]: regex,
  }));

  return {
    'preferences.profilePublic': true,
    'preferences.searchable': true,
    $or: [
      { username: regex },
      { displayName: regex },
      {
        $and: [{ 'preferences.publicProfile.headline': true }, { 'profile.headline': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.role': true }, { 'profile.role': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.organization': true }, { 'profile.organization': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.currentFocus': true }, { 'profile.currentFocus': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.focusAreas': true }, { 'profile.focusAreas': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.bio': true }, { 'profile.bio': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.location': true }, { 'profile.location': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.linkedAccounts': true }, { $or: linkedClauses }],
      },
    ],
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
  'email username displayName isVerified verificationToken verificationTokenExpires emailDelivery passwordResetToken passwordResetTokenExpires passwordResetRequestedAt lastLoginAt lastLoginIp recentLogins loginDayCounts knownDevices auditEvents profile linkedAccounts preferences security refreshTokenVersion refreshSessions createdAt updatedAt password';

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

const revokeAllTrackedSessions = (user) => {
  if (!user) return;
  user.refreshTokenVersion += 1;
  user.refreshSessions = [];
};

const getPasswordResetCooldownRemainingMs = (user) => {
  const requestedAt = user?.passwordResetRequestedAt
    ? new Date(user.passwordResetRequestedAt).getTime()
    : 0;
  if (!requestedAt) return 0;
  return Math.max(0, requestedAt + PASSWORD_RESET_EMAIL_COOLDOWN_MS - Date.now());
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

const buildEmailChangeSecurityDetails = (req, previousEmail = '', nextEmail = '') =>
  [
    previousEmail ? `Previous email: ${previousEmail}` : '',
    nextEmail ? `New email: ${nextEmail}` : '',
    `Time: ${new Date().toUTCString()}`,
    `IP address: ${parseClientIp(req) || 'Unknown'}`,
  ].filter(Boolean);

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

    if (containsBlockedNameTerm(requestedUsername)) {
      return res.status(400).json({ message: USERNAME_MODERATION_MESSAGE });
    }

    if (hasOwn(req.body || {}, 'displayName') && containsBlockedNameTerm(req.body?.displayName)) {
      return res.status(400).json({ message: DISPLAY_NAME_MODERATION_MESSAGE });
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
    const verification = prepareEmailVerification(user);
    appendAuditEvent(user, req, 'register', 'Account created. Email verification required before sign-in.', {
      username: getDisplayableUsername(user),
    });
    await user.save();
    const verificationDelivery = await sendVerificationEmail(user, req, verification);

    return res.status(201).json({
      message: getVerificationDeliveryMessage(
        'Registration successful. Check your inbox to verify your email before signing in.',
        'Registration successful. Check your inbox for the verification email that was already sent.',
        'Registration successful, but the verification email could not be sent right now. Try signing in later to request another verification email.',
        verificationDelivery
      ),
      authenticated: false,
      requiresVerification: true,
      verificationEmail: serializeVerificationDelivery(verificationDelivery),
    });
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
  const mfaCode = sanitizeMfaCode(req.body?.mfaCode);
  const backupCode = sanitizeBackupCode(req.body?.backupCode);

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

    await ensureUserIdentityFields(user);

    if (!user.isVerified) {
      await clearLoginFailures(rateKey);

      let verificationDelivery = { sent: false, reason: 'cooldown' };
      if (!(hasPendingEmailVerification(user) && getVerificationEmailCooldownRemainingMs(user) > 0)) {
        const verification = prepareEmailVerification(user);
        revokeAllTrackedSessions(user);
        appendAuditEvent(
          user,
          req,
          'login_blocked_unverified',
          'Sign-in blocked until email verification is completed.',
          { identifier }
        );
        await user.save();
        verificationDelivery = await sendVerificationEmail(user, req, verification);
      }

      clearRefreshCookie(res, req);

      return res.status(403).json({
        message: getVerificationDeliveryMessage(
          'Verify your email before signing in. A fresh verification link has been sent.',
          'Verify your email before signing in. Check your inbox for the verification link that was already sent recently.',
          'Verify your email before signing in. We could not send a new verification email right now.',
          verificationDelivery
        ),
        authenticated: false,
        requiresVerification: true,
        verificationEmail: serializeVerificationDelivery(verificationDelivery),
      });
    }

    const mfaEnabled = Boolean(user?.security?.mfa?.enabled && user?.security?.mfa?.secret);
    if (mfaEnabled) {
      const mfaResult = verifyMfaAttempt(user, { mfaCode, backupCode });
      if (!mfaResult.ok) {
        appendAuditEvent(user, req, 'mfa_challenge', 'Additional verification required for sign-in.', {
          identifier,
        });
        await user.save();
        return res.status(401).json({
          message: mfaCode || backupCode ? 'Invalid MFA code.' : 'Enter your MFA code to continue.',
          mfaRequired: true,
        });
      }

      user.security.mfa.lastUsedAt = new Date();

      if (mfaResult.method === 'backup_code') {
        appendAuditEvent(user, req, 'mfa_backup_code_used', 'A backup code was used for sign-in.');
      }
    }

    await clearLoginFailures(rateKey);

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
    if (getPasswordResetCooldownRemainingMs(user) > 0) {
      return res.status(200).json({ message: genericMessage });
    }

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

exports.publicResendVerificationEmail = async (req, res) => {
  const identifier = normalizeLoginIdentifier(
    req.body?.identifier || req.body?.email || req.body?.username
  );
  const genericMessage =
    'If that sign-in belongs to an unverified account, a verification link will be sent shortly.';

  try {
    if (!identifier || (!isValidEmail(identifier) && !isValidUsername(identifier))) {
      return res.status(200).json({ message: genericMessage });
    }

    const user = await findUserByLoginIdentifier(identifier);
    if (!user || user.isVerified) {
      return res.status(200).json({ message: genericMessage });
    }

    await ensureUserIdentityFields(user);
    if (!(hasPendingEmailVerification(user) && getVerificationEmailCooldownRemainingMs(user) > 0)) {
      const verification = prepareEmailVerification(user);
      revokeAllTrackedSessions(user);
      appendAuditEvent(
        user,
        req,
        'verification_resent_public',
        'Verification email resent from the public sign-in flow.'
      );
      await user.save();
      await sendVerificationEmail(user, req, verification);
    }

    clearRefreshCookie(res, req);

    return res.status(200).json({ message: genericMessage });
  } catch (err) {
    console.error('Public resend verification email error:', err);
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
      const users = await User.find({
        'preferences.profilePublic': true,
        'preferences.searchable': true,
      })
        .select('username displayName profile linkedAccounts preferences createdAt updatedAt')
        .sort({ updatedAt: -1, _id: -1 })
        .limit(12)
        .lean();

      return res.json({
        message: 'Directory loaded.',
        query: '',
        isDirectory: true,
        results: users.map((user) => buildPublicProfilePayload(user)),
      });
    }

    const regex = new RegExp(escapeRegex(query), 'i');
    const users = await User.find(buildPublicSearchQuery(regex))
      .select('username displayName profile linkedAccounts preferences createdAt updatedAt')
      .sort({ updatedAt: -1, _id: -1 })
      .limit(48)
      .lean();

    const rankedUsers = users
      .map((user) => ({
        user,
        score: scorePublicProfileMatch(user, query),
        updatedAt: new Date(user?.updatedAt || user?.createdAt || 0).getTime(),
      }))
      .filter((entry) => entry.score > 0)
      .sort((left, right) => right.score - left.score || right.updatedAt - left.updatedAt)
      .slice(0, 12)
      .map((entry) => entry.user);

    return res.json({
      message: 'Search loaded.',
      query,
      isDirectory: false,
      results: rankedUsers.map((user) => buildPublicProfilePayload(user)),
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
      .select('username displayName profile linkedAccounts preferences createdAt updatedAt')
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

    if (!session.user.isVerified) {
      clearRefreshCookie(res, req);
      return res.status(200).json({
        authenticated: false,
        requiresVerification: true,
        message: 'Verify your email before signing in.',
      });
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
    const previousEmail = sanitizeText(user.email, 320);
    const previousEmailWasVerified = Boolean(user.isVerified);

    if (hasOwn(incoming, 'username')) {
      if (!normalizeUsername(incoming.username)) {
        return res.status(400).json({ message: USERNAME_VALIDATION_MESSAGE });
      }
      if (containsBlockedNameTerm(incoming.username)) {
        return res.status(400).json({ message: USERNAME_MODERATION_MESSAGE });
      }
      await applyUsernameChange(user, incoming.username);
    }

    if (hasOwn(incoming, 'displayName')) {
      const displayName = sanitizeText(incoming.displayName, 60);
      if (displayName.length < 2) {
        return res.status(400).json({ message: 'Display name must be at least 2 characters.' });
      }
      if (containsBlockedNameTerm(displayName)) {
        return res.status(400).json({ message: DISPLAY_NAME_MODERATION_MESSAGE });
      }
      user.displayName = displayName;
    }

    if (hasOwn(incoming, 'email')) {
      emailChanged = await applyEmailChange(user, incoming.email, currentPassword);
      if (emailChanged) {
        verification = prepareEmailVerification(user);
        revokeAllTrackedSessions(user);
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
      if (previousEmailWasVerified && previousEmail && previousEmail !== user.email) {
        await sendSecurityAlertEmail(
          user,
          'Your Continental ID email was changed',
          'Email change detected',
          'The email address on your Continental ID account was changed. If this was not you, secure your account immediately.',
          buildEmailChangeSecurityDetails(req, previousEmail, user.email),
          { emailOverride: previousEmail }
        );
      }

      clearRefreshCookie(res, req);
    }

    const message = verification
      ? getVerificationDeliveryMessage(
          'Profile updated. Verify your new email before signing in again.',
          'Profile updated. Check your inbox for the verification email that was already sent.',
          'Profile updated, but the verification email could not be sent right now.',
          verificationDelivery
        )
      : 'Profile updated.';

    return sendUserResponse(res, 200, message, user, {
      verificationEmail: verification ? serializeVerificationDelivery(verificationDelivery) : undefined,
      forceRelogin: emailChanged,
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

    const previousEmail = sanitizeText(user.email, 320);
    const previousEmailWasVerified = Boolean(user.isVerified);
    const emailChanged = await applyEmailChange(user, email, currentPassword);
    let verification = null;
    if (emailChanged) {
      verification = prepareEmailVerification(user);
      revokeAllTrackedSessions(user);
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
      if (previousEmailWasVerified && previousEmail && previousEmail !== user.email) {
        await sendSecurityAlertEmail(
          user,
          'Your Continental ID email was changed',
          'Email change detected',
          'The email address on your Continental ID account was changed. If this was not you, secure your account immediately.',
          buildEmailChangeSecurityDetails(req, previousEmail, user.email),
          { emailOverride: previousEmail }
        );
      }

      clearRefreshCookie(res, req);
    }

    const message = verification
      ? getVerificationDeliveryMessage(
          'Email updated. Verify your new email before signing in again.',
          'Email updated. Check your inbox for the verification email that was already sent.',
          'Email updated, but the verification email could not be sent right now.',
          verificationDelivery
        )
      : 'Email updated.';

    return sendUserResponse(res, 200, message, user, {
      verificationEmail: verification ? serializeVerificationDelivery(verificationDelivery) : undefined,
      forceRelogin: emailChanged,
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

    let verificationDelivery = { sent: false, reason: 'cooldown' };
    if (!(hasPendingEmailVerification(user) && getVerificationEmailCooldownRemainingMs(user) > 0)) {
      const verification = prepareEmailVerification(user);
      appendAuditEvent(user, req, 'verification_resent', 'Verification email resent.');
      await user.save();
      verificationDelivery = await sendVerificationEmail(user, req, verification);
    }

    const message = getVerificationDeliveryMessage(
      'Verification email sent.',
      'A verification email was already sent recently. Check your inbox before requesting another one.',
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
      mfa: payload.security.mfa,
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

exports.beginMfaSetup = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (user.security?.mfa?.enabled && user.security?.mfa?.secret) {
      return res.status(400).json({ message: 'MFA is already enabled on this account.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    const secret = generateMfaSecret();
    const backupCodes = generateBackupCodes(MFA_BACKUP_CODE_COUNT);

    user.security.mfa.pendingSecret = secret;
    user.security.mfa.pendingBackupCodes = hashBackupCodes(backupCodes);
    user.security.mfa.pendingCreatedAt = new Date();
    await user.save();

    return res.json({
      message: 'MFA setup ready.',
      setup: buildMfaSetupPayload(user, secret, backupCodes),
      mfa: getMfaState(user),
    });
  } catch (err) {
    console.error('Begin MFA setup error:', err);
    return res.status(500).json({ message: 'Failed to start MFA setup.' });
  }
};

exports.enableMfa = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const code = sanitizeMfaCode(req.body?.code);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const pendingSecret = sanitizeText(user?.security?.mfa?.pendingSecret, 120);
    if (!pendingSecret) {
      return res.status(400).json({ message: 'Start MFA setup before enabling it.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    if (!verifyTotp({ secret: pendingSecret, token: code })) {
      return res.status(400).json({ message: 'Invalid MFA code.' });
    }

    user.security.mfa.enabled = true;
    user.security.mfa.secret = pendingSecret;
    user.security.mfa.backupCodes = Array.isArray(user.security.mfa.pendingBackupCodes)
      ? [...user.security.mfa.pendingBackupCodes]
      : [];
    user.security.mfa.pendingSecret = '';
    user.security.mfa.pendingBackupCodes = [];
    user.security.mfa.pendingCreatedAt = null;
    user.security.mfa.enrolledAt = new Date();
    user.security.mfa.lastUsedAt = new Date();

    appendAuditEvent(user, req, 'mfa_enabled', 'Multi-factor authentication enabled.');
    await user.save();

    return sendUserResponse(res, 200, 'Multi-factor authentication enabled.', user);
  } catch (err) {
    console.error('Enable MFA error:', err);
    return res.status(500).json({ message: 'Failed to enable MFA.' });
  }
};

exports.disableMfa = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const code = sanitizeMfaCode(req.body?.code);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (!user.security?.mfa?.enabled || !user.security?.mfa?.secret) {
      return res.status(400).json({ message: 'MFA is not enabled.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    if (!verifyTotp({ secret: user.security.mfa.secret, token: code })) {
      return res.status(400).json({ message: 'Invalid MFA code.' });
    }

    user.security.mfa.enabled = false;
    user.security.mfa.secret = '';
    user.security.mfa.backupCodes = [];
    user.security.mfa.pendingSecret = '';
    user.security.mfa.pendingBackupCodes = [];
    user.security.mfa.pendingCreatedAt = null;
    user.security.mfa.enrolledAt = null;
    user.security.mfa.lastUsedAt = null;

    appendAuditEvent(user, req, 'mfa_disabled', 'Multi-factor authentication disabled.');
    await user.save();

    return sendUserResponse(res, 200, 'Multi-factor authentication disabled.', user);
  } catch (err) {
    console.error('Disable MFA error:', err);
    return res.status(500).json({ message: 'Failed to disable MFA.' });
  }
};

exports.regenerateMfaBackupCodes = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const code = sanitizeMfaCode(req.body?.code);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (!user.security?.mfa?.enabled || !user.security?.mfa?.secret) {
      return res.status(400).json({ message: 'MFA is not enabled.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    if (!verifyTotp({ secret: user.security.mfa.secret, token: code })) {
      return res.status(400).json({ message: 'Invalid MFA code.' });
    }

    const backupCodes = generateBackupCodes(MFA_BACKUP_CODE_COUNT);
    user.security.mfa.backupCodes = hashBackupCodes(backupCodes);
    appendAuditEvent(user, req, 'mfa_backup_codes_regenerated', 'Backup codes regenerated.');
    await user.save();

    return res.json({
      message: 'Backup codes regenerated.',
      backupCodes,
      mfa: getMfaState(user),
    });
  } catch (err) {
    console.error('Regenerate MFA backup codes error:', err);
    return res.status(500).json({ message: 'Failed to regenerate backup codes.' });
  }
};

exports.getDevices = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const sessions = Array.isArray(user.refreshSessions) ? user.refreshSessions : [];
    const currentSession = findRefreshSession(user, req.user?.sid);
    const currentFingerprint = sanitizeText(currentSession?.deviceFingerprint, 128);
    const devices = (Array.isArray(user.knownDevices) ? user.knownDevices : [])
      .map((device) => serializeDevice(device, sessions, currentFingerprint))
      .sort((left, right) => {
        const leftTime = new Date(left.lastSeenAt || 0).getTime();
        const rightTime = new Date(right.lastSeenAt || 0).getTime();
        return rightTime - leftTime;
      });

    return res.json({
      message: 'Devices loaded.',
      devices,
    });
  } catch (err) {
    console.error('Get devices error:', err);
    return res.status(500).json({ message: 'Failed to load devices.' });
  }
};

exports.updateDevice = async (req, res) => {
  const fingerprint = sanitizeText(req.params?.fingerprint, 128);
  const nextLabel = sanitizeText(req.body?.label, 60);
  const nextTrusted = hasOwn(req.body || {}, 'trusted') ? Boolean(req.body.trusted) : null;

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const devices = Array.isArray(user.knownDevices) ? [...user.knownDevices] : [];
    const deviceIndex = devices.findIndex((device) => sanitizeText(device?.fingerprint, 128) === fingerprint);
    if (deviceIndex < 0) {
      return res.status(404).json({ message: 'Device not found.' });
    }

    const device = devices[deviceIndex];
    devices[deviceIndex] = {
      ...device,
      label: nextLabel || sanitizeText(device?.label, 60) || 'Browser device',
      trusted: nextTrusted === null ? Boolean(device?.trusted) : nextTrusted,
    };
    user.knownDevices = devices;

    if (nextLabel) {
      user.refreshSessions = (Array.isArray(user.refreshSessions) ? user.refreshSessions : []).map((session) =>
        sanitizeText(session?.deviceFingerprint, 128) === fingerprint
          ? { ...session, label: nextLabel }
          : session
      );
    }

    appendAuditEvent(user, req, 'device_updated', 'Device settings updated.', {
      trusted: devices[deviceIndex].trusted,
    });
    await user.save();

    return res.json({
      message: 'Device updated.',
      device: serializeDevice(
        devices[deviceIndex],
        Array.isArray(user.refreshSessions) ? user.refreshSessions : [],
        sanitizeText(findRefreshSession(user, req.user?.sid)?.deviceFingerprint, 128)
      ),
    });
  } catch (err) {
    console.error('Update device error:', err);
    return res.status(500).json({ message: 'Failed to update device.' });
  }
};

exports.deleteDevice = async (req, res) => {
  const fingerprint = sanitizeText(req.params?.fingerprint, 128);
  const revokeSessions = !hasOwn(req.body || {}, 'revokeSessions') || Boolean(req.body.revokeSessions);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const deviceExists = (Array.isArray(user.knownDevices) ? user.knownDevices : []).some(
      (device) => sanitizeText(device?.fingerprint, 128) === fingerprint
    );
    if (!deviceExists) {
      return res.status(404).json({ message: 'Device not found.' });
    }

    user.knownDevices = (Array.isArray(user.knownDevices) ? user.knownDevices : []).filter(
      (device) => sanitizeText(device?.fingerprint, 128) !== fingerprint
    );

    let forceRelogin = false;
    if (revokeSessions) {
      const currentSid = sanitizeText(req.user?.sid, 120);
      user.refreshSessions = (Array.isArray(user.refreshSessions) ? user.refreshSessions : []).filter((session) => {
        const isTarget = sanitizeText(session?.deviceFingerprint, 128) === fingerprint;
        if (isTarget && sanitizeText(session?.sid, 120) === currentSid) {
          forceRelogin = true;
        }
        return !isTarget;
      });
    }

    appendAuditEvent(user, req, 'device_removed', 'Device removed.', {
      revokeSessions,
    });
    await user.save();

    if (forceRelogin) {
      clearRefreshCookie(res, req);
    }

    return res.json({
      message: revokeSessions ? 'Device removed and sessions revoked.' : 'Device removed.',
      forceRelogin,
    });
  } catch (err) {
    console.error('Delete device error:', err);
    return res.status(500).json({ message: 'Failed to remove device.' });
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
