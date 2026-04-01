const crypto = require('crypto');
const User = require('../models/User');

const ENCRYPTED_MFA_SECRET_PREFIX = 'enc:';
const PROTECTED_BACKUP_CODE_PREFIX = 'v2:';
const LEGACY_BACKUP_CODE_HASH_PATTERN = /^[a-f0-9]{64}$/i;

const hashToken = (value) =>
  crypto.createHash('sha256').update(String(value || '')).digest('hex');

const getSecurityKeyMaterial = () =>
  String(
    process.env.MFA_SECRET_ENCRYPTION_KEY ||
      process.env.BACKUP_CODE_SECRET ||
      process.env.REFRESH_TOKEN_SECRET ||
      process.env.JWT_SECRET ||
      ''
  ).trim();

const deriveScopedKey = (scope) =>
  crypto
    .createHash('sha256')
    .update(`${scope}:${getSecurityKeyMaterial()}`)
    .digest();

const hasEncryptedMfaSecret = (value) =>
  String(value || '').startsWith(ENCRYPTED_MFA_SECRET_PREFIX);

const encryptMfaSecret = (value) => {
  const secret = String(value || '').trim();
  if (!secret) return '';
  if (hasEncryptedMfaSecret(secret)) return secret;

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveScopedKey('mfa-secret'), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return `${ENCRYPTED_MFA_SECRET_PREFIX}${iv.toString('base64url')}.${tag.toString('base64url')}.${ciphertext.toString('base64url')}`;
};

const decryptMfaSecret = (value) => {
  const secret = String(value || '').trim();
  if (!secret) return '';
  if (!hasEncryptedMfaSecret(secret)) return secret;

  const payload = secret.slice(ENCRYPTED_MFA_SECRET_PREFIX.length);
  const [ivPart, tagPart, ciphertextPart] = payload.split('.');
  if (!ivPart || !tagPart || !ciphertextPart) return '';

  try {
    const iv = Buffer.from(ivPart, 'base64url');
    const tag = Buffer.from(tagPart, 'base64url');
    const ciphertext = Buffer.from(ciphertextPart, 'base64url');
    const decipher = crypto.createDecipheriv('aes-256-gcm', deriveScopedKey('mfa-secret'), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    return '';
  }
};

const protectBackupCodeHash = (hash) => {
  const normalizedHash = String(hash || '').trim().toLowerCase();
  if (!LEGACY_BACKUP_CODE_HASH_PATTERN.test(normalizedHash)) {
    return '';
  }

  const protectedHash = crypto
    .createHmac('sha256', deriveScopedKey('backup-code'))
    .update(normalizedHash)
    .digest('hex');

  return `${PROTECTED_BACKUP_CODE_PREFIX}${protectedHash}`;
};

const hashBackupCodeForStorage = (code) => {
  const normalizedCode = String(code || '').trim();
  if (!normalizedCode) {
    return '';
  }

  return protectBackupCodeHash(hashToken(normalizedCode));
};

const verifyStoredBackupCodeHash = (storedHash, code) => {
  const normalizedStoredHash = String(storedHash || '').trim();
  if (!normalizedStoredHash || !code) return false;

  if (normalizedStoredHash.startsWith(PROTECTED_BACKUP_CODE_PREFIX)) {
    return normalizedStoredHash === hashBackupCodeForStorage(code);
  }

  if (LEGACY_BACKUP_CODE_HASH_PATTERN.test(normalizedStoredHash)) {
    return normalizedStoredHash.toLowerCase() === hashToken(code);
  }

  return false;
};

const normalizeBackupCodeHashList = (codes = []) =>
  (Array.isArray(codes) ? codes : [])
    .map((entry) => {
      const normalizedEntry = String(entry || '').trim();
      if (!normalizedEntry) return '';
      if (normalizedEntry.startsWith(PROTECTED_BACKUP_CODE_PREFIX)) return normalizedEntry;
      return protectBackupCodeHash(normalizedEntry);
    })
    .filter(Boolean);

const arraysEqual = (left = [], right = []) =>
  left.length === right.length && left.every((value, index) => value === right[index]);

const normalizeUserSecurityState = (user) => {
  if (!user?.security?.mfa) {
    return false;
  }

  let changed = false;

  const currentSecret = String(user.security.mfa.secret || '').trim();
  if (currentSecret && !hasEncryptedMfaSecret(currentSecret)) {
    user.security.mfa.secret = encryptMfaSecret(currentSecret);
    changed = true;
  }

  const pendingSecret = String(user.security.mfa.pendingSecret || '').trim();
  if (pendingSecret && !hasEncryptedMfaSecret(pendingSecret)) {
    user.security.mfa.pendingSecret = encryptMfaSecret(pendingSecret);
    changed = true;
  }

  const normalizedBackupCodes = normalizeBackupCodeHashList(user.security.mfa.backupCodes);
  const currentBackupCodes = Array.isArray(user.security.mfa.backupCodes)
    ? user.security.mfa.backupCodes.map((value) => String(value || '').trim()).filter(Boolean)
    : [];
  if (!arraysEqual(normalizedBackupCodes, currentBackupCodes)) {
    user.security.mfa.backupCodes = normalizedBackupCodes;
    changed = true;
  }

  const normalizedPendingBackupCodes = normalizeBackupCodeHashList(user.security.mfa.pendingBackupCodes);
  const currentPendingBackupCodes = Array.isArray(user.security.mfa.pendingBackupCodes)
    ? user.security.mfa.pendingBackupCodes.map((value) => String(value || '').trim()).filter(Boolean)
    : [];
  if (!arraysEqual(normalizedPendingBackupCodes, currentPendingBackupCodes)) {
    user.security.mfa.pendingBackupCodes = normalizedPendingBackupCodes;
    changed = true;
  }

  return changed;
};

const migrateUsersToLatestSecurityState = async ({ logger = console } = {}) => {
  let scanned = 0;
  let updated = 0;

  const cursor = User.find({}).cursor();

  for await (const user of cursor) {
    scanned += 1;
    if (!normalizeUserSecurityState(user)) {
      continue;
    }

    await user.save();
    updated += 1;
  }

  const message = `User security migration complete. Scanned ${scanned} users, updated ${updated}.`;
  if (typeof logger?.info === 'function') {
    logger.info(message);
  } else if (typeof logger?.log === 'function') {
    logger.log(message);
  }

  return { scanned, updated };
};

module.exports = {
  decryptMfaSecret,
  encryptMfaSecret,
  hashBackupCodeForStorage,
  migrateUsersToLatestSecurityState,
  normalizeUserSecurityState,
  verifyStoredBackupCodeHash,
};
