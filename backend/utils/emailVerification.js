const crypto = require('crypto');

const DEFAULT_EMAIL_VERIFICATION_TTL_MS = 24 * 60 * 60 * 1000;

const getEmailVerificationTtlMs = () => {
  const ttlMs = Number(process.env.EMAIL_VERIFICATION_TTL_MS);
  if (Number.isFinite(ttlMs) && ttlMs > 0) {
    return ttlMs;
  }

  return DEFAULT_EMAIL_VERIFICATION_TTL_MS;
};

const hashEmailVerificationToken = (token) =>
  crypto.createHash('sha256').update(String(token || '')).digest('hex');

const createEmailVerificationToken = () => {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + getEmailVerificationTtlMs());

  return {
    token,
    hashedToken: hashEmailVerificationToken(token),
    expiresAt,
  };
};

module.exports = {
  createEmailVerificationToken,
  getEmailVerificationTtlMs,
  hashEmailVerificationToken,
};
