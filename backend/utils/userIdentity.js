const User = require('../models/User');

const USERNAME_MIN_LENGTH = 3;
const USERNAME_MAX_LENGTH = 30;
const USERNAME_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{1,28}[a-z0-9])?$/;
const USERNAME_VALIDATION_MESSAGE =
  'Username must be 3-30 characters and use only letters, numbers, dots, hyphens, or underscores.';

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj || {}, key);
const toObjectIdString = (value) => String(value || '');
const sanitizeText = (value, maxLength = 120) => String(value || '').trim().slice(0, maxLength);
const normalizeEmail = (email) => String(email || '').trim().toLowerCase();
const normalizeUsername = (value) => sanitizeText(value, USERNAME_MAX_LENGTH).toLowerCase();
const isValidUsername = (value) => USERNAME_PATTERN.test(normalizeUsername(value));

const slugifyUsernameSeed = (value) =>
  String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '.')
    .replace(/[._-]{2,}/g, '.')
    .replace(/^[._-]+|[._-]+$/g, '')
    .slice(0, USERNAME_MAX_LENGTH);

const trimUsernameBase = (value) =>
  slugifyUsernameSeed(value)
    .replace(/^[._-]+|[._-]+$/g, '')
    .slice(0, USERNAME_MAX_LENGTH);

const buildUsernameBase = (...candidates) => {
  for (const candidate of candidates) {
    const normalized = trimUsernameBase(candidate);
    if (normalized.length >= USERNAME_MIN_LENGTH) {
      return normalized;
    }
  }

  return 'user';
};

const appendUsernameSuffix = (base, suffix) => {
  const safeSuffix = sanitizeText(suffix, USERNAME_MAX_LENGTH).replace(/[^a-z0-9]/gi, '').toLowerCase();
  const normalizedBase = buildUsernameBase(base);

  if (!safeSuffix) {
    return normalizedBase;
  }

  const maxBaseLength = Math.max(1, USERNAME_MAX_LENGTH - safeSuffix.length);
  const trimmedBase = trimUsernameBase(normalizedBase).slice(0, maxBaseLength).replace(/[._-]+$/g, '') || 'user';
  const candidate = `${trimmedBase}${safeSuffix}`.slice(0, USERNAME_MAX_LENGTH);

  return isValidUsername(candidate) ? candidate : buildUsernameBase(candidate, `user${safeSuffix}`);
};

const buildFallbackDisplayName = (email) => {
  const [localPart] = normalizeEmail(email).split('@');
  return sanitizeText(localPart, 60) || 'User';
};

const normalizeIdentityProfile = (profile = {}) => ({
  ...(profile?.toObject ? profile.toObject() : profile || {}),
  avatar: sanitizeText(profile?.avatar, 350000),
  headline: sanitizeText(profile?.headline, 100),
  pronouns: sanitizeText(profile?.pronouns, 40),
});

const getDisplayableUsername = (user) => {
  const stored = normalizeUsername(user?.username);
  if (isValidUsername(stored)) {
    return stored;
  }

  const emailLocalPart = normalizeEmail(user?.email).split('@')[0];
  const objectIdSuffix = toObjectIdString(user?._id).slice(-6).toLowerCase();

  return buildUsernameBase(
    user?.displayName,
    emailLocalPart,
    objectIdSuffix ? `user${objectIdSuffix}` : '',
    'user'
  );
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

const ensureStoredUsername = async (user) => {
  if (!user) return false;

  const current = normalizeUsername(user.username);
  if (isValidUsername(current)) {
    if (user.username !== current) {
      user.username = current;
      return true;
    }
    return false;
  }

  const base = getDisplayableUsername(user);
  const suffixSeed = toObjectIdString(user._id).slice(-6).toLowerCase();
  let candidate = base;
  let attempt = 0;

  while (await isUsernameTaken(candidate, user._id)) {
    attempt += 1;
    candidate = appendUsernameSuffix(base, attempt === 1 && suffixSeed ? suffixSeed : String(attempt + 1));
  }

  user.username = candidate;
  return true;
};

const ensureUserIdentityFields = async (user) => {
  if (!user) return false;

  let changed = false;

  if (!sanitizeText(user.displayName, 60)) {
    const fallbackDisplayName = buildFallbackDisplayName(user.email);
    if (user.displayName !== fallbackDisplayName) {
      user.displayName = fallbackDisplayName;
      changed = true;
    }
  }

  const normalizedProfile = normalizeIdentityProfile(user.profile || {});
  const currentProfile = user.profile?.toObject ? user.profile.toObject() : user.profile || {};
  const needsProfileDefaults =
    !hasOwn(currentProfile, 'avatar') ||
    !hasOwn(currentProfile, 'headline') ||
    !hasOwn(currentProfile, 'pronouns');
  if (
    needsProfileDefaults ||
    sanitizeText(currentProfile.avatar, 350000) !== normalizedProfile.avatar ||
    sanitizeText(currentProfile.headline, 100) !== normalizedProfile.headline ||
    sanitizeText(currentProfile.pronouns, 40) !== normalizedProfile.pronouns
  ) {
    user.profile = {
      ...currentProfile,
      ...normalizedProfile,
    };
    changed = true;
  }

  if (await ensureStoredUsername(user)) {
    changed = true;
  }

  return changed;
};

const migrateUsersToLatestIdentity = async ({ logger = console } = {}) => {
  let scanned = 0;
  let updated = 0;

  const cursor = User.find({}).cursor();

  for await (const user of cursor) {
    scanned += 1;
    const changed = await ensureUserIdentityFields(user);
    if (!changed) {
      continue;
    }

    await user.save();
    updated += 1;
  }

  if (typeof logger?.info === 'function') {
    logger.info(`User identity migration complete. Scanned ${scanned} users, updated ${updated}.`);
  } else if (typeof logger?.log === 'function') {
    logger.log(`User identity migration complete. Scanned ${scanned} users, updated ${updated}.`);
  }

  return { scanned, updated };
};

module.exports = {
  USERNAME_VALIDATION_MESSAGE,
  getDisplayableUsername,
  ensureStoredUsername,
  ensureUserIdentityFields,
  isValidUsername,
  migrateUsersToLatestIdentity,
  normalizeUsername,
};
