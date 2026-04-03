const User = require('../models/User');

const USERNAME_MIN_LENGTH = 3;
const USERNAME_MAX_LENGTH = 30;
const USERNAME_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{1,28}[a-z0-9])?$/;
const USERNAME_VALIDATION_MESSAGE =
  'Username must be 3-30 characters and use only letters, numbers, dots, hyphens, or underscores.';
const USERNAME_MODERATION_MESSAGE =
  'Choose a different username. Usernames cannot contain offensive or hateful language.';
const DISPLAY_NAME_MODERATION_MESSAGE =
  'Choose a different display name. Display names cannot contain offensive or hateful language.';
const BLOCKED_NAME_FRAGMENTS = [
  'anal',
  'anus',
  'arse',
  'asshole',
  'bastard',
  'beaner',
  'bitch',
  'bollock',
  'boner',
  'boob',
  'buttplug',
  'chink',
  'clit',
  'cock',
  'coon',
  'crackhead',
  'cum',
  'cuck',
  'cunt',
  'deepthroat',
  'dick',
  'dildo',
  'dyke',
  'ejaculate',
  'fag',
  'faggot',
  'felch',
  'fuck',
  'gangbang',
  'genital',
  'gook',
  'handjob',
  'hentai',
  'hitler',
  'jackoff',
  'jizz',
  'kike',
  'kkk',
  'nazi',
  'nigga',
  'nigger',
  'nutsack',
  'orgasm',
  'penis',
  'piss',
  'porn',
  'prick',
  'pussy',
  'queef',
  'rapist',
  'rape',
  'retard',
  'rimjob',
  'scrotum',
  'sex',
  'shit',
  'slut',
  'spic',
  'tit',
  'tranny',
  'twat',
  'vagina',
  'wank',
  'whore',
];

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj || {}, key);
const toObjectIdString = (value) => String(value || '');
const sanitizeText = (value, maxLength = 120) => String(value || '').trim().slice(0, maxLength);
const normalizeEmail = (email) => String(email || '').trim().toLowerCase();
const normalizeUsername = (value) => sanitizeText(value, USERNAME_MAX_LENGTH).toLowerCase();
const isValidUsername = (value) => USERNAME_PATTERN.test(normalizeUsername(value));
const normalizeForModeration = (value) =>
  sanitizeText(value, 120)
    .toLowerCase()
    .replace(/[0134@5$7+8]/g, (char) => {
      if (char === '0') return 'o';
      if (char === '1') return 'i';
      if (char === '3') return 'e';
      if (char === '4' || char === '@') return 'a';
      if (char === '5' || char === '$') return 's';
      if (char === '7' || char === '+') return 't';
      if (char === '8') return 'b';
      return char;
    })
    .replace(/[^a-z0-9]+/g, '')
    .replace(/(.)\1{2,}/g, '$1');
const buildModerationVariants = (value) => {
  const normalized = normalizeForModeration(value);
  if (!normalized) return [];

  const collapsedPairs = normalized.replace(/(.)\1+/g, '$1');
  return Array.from(new Set([normalized, collapsedPairs])).filter(Boolean);
};
const containsBlockedNameTerm = (value) => {
  const variants = buildModerationVariants(value);
  if (!variants.length) return false;

  return variants.some((variant) =>
    BLOCKED_NAME_FRAGMENTS.some((fragment) => variant.includes(fragment))
  );
};

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
    if (normalized.length >= USERNAME_MIN_LENGTH && !containsBlockedNameTerm(normalized)) {
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
  const fallback = sanitizeText(localPart, 60);
  if (fallback && !containsBlockedNameTerm(fallback)) {
    return fallback;
  }

  return 'User';
};

const normalizeIdentityAvatarMeta = (meta = {}, avatar = '') => {
  const source = meta && typeof meta === 'object' ? meta : {};
  const width = Math.max(0, Math.min(4096, Math.round(Number(source.width) || 0)));
  const height = Math.max(0, Math.min(4096, Math.round(Number(source.height) || 0)));
  const updatedAt = source.updatedAt ? new Date(source.updatedAt) : null;
  const kind = sanitizeText(source.kind, 24).toLowerCase();

  return {
    kind: avatar ? kind || (String(avatar).startsWith('data:image/') ? 'upload' : 'url') : '',
    mimeType: /^image\/[-+.\w]+$/i.test(sanitizeText(source.mimeType, 40))
      ? sanitizeText(source.mimeType, 40).toLowerCase()
      : '',
    width,
    height,
    updatedAt: updatedAt && !Number.isNaN(updatedAt.getTime()) ? updatedAt : null,
  };
};

const serializeIdentityAvatarMeta = (meta = {}) => {
  const parsedUpdatedAt = meta.updatedAt ? new Date(meta.updatedAt) : null;
  return JSON.stringify({
    kind: sanitizeText(meta.kind, 24).toLowerCase(),
    mimeType: sanitizeText(meta.mimeType, 40).toLowerCase(),
    width: Math.max(0, Math.min(4096, Math.round(Number(meta.width) || 0))),
    height: Math.max(0, Math.min(4096, Math.round(Number(meta.height) || 0))),
    updatedAt:
      parsedUpdatedAt && !Number.isNaN(parsedUpdatedAt.getTime())
        ? parsedUpdatedAt.toISOString()
        : null,
  });
};

const normalizeIdentityProfile = (profile = {}) => ({
  ...(profile?.toObject ? profile.toObject() : profile || {}),
  avatar: sanitizeText(profile?.avatar, 350000),
  avatarMeta: normalizeIdentityAvatarMeta(profile?.avatarMeta, profile?.avatar),
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
    !hasOwn(currentProfile, 'avatarMeta') ||
    !hasOwn(currentProfile, 'headline') ||
    !hasOwn(currentProfile, 'pronouns');
  if (
    needsProfileDefaults ||
    sanitizeText(currentProfile.avatar, 350000) !== normalizedProfile.avatar ||
    serializeIdentityAvatarMeta(currentProfile.avatarMeta) !== serializeIdentityAvatarMeta(normalizedProfile.avatarMeta) ||
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
  DISPLAY_NAME_MODERATION_MESSAGE,
  USERNAME_VALIDATION_MESSAGE,
  USERNAME_MODERATION_MESSAGE,
  containsBlockedNameTerm,
  getDisplayableUsername,
  ensureStoredUsername,
  ensureUserIdentityFields,
  isValidUsername,
  migrateUsersToLatestIdentity,
  normalizeUsername,
};
