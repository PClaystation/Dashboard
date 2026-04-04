const { getDisplayableUsername } = require('./userIdentity');

const DISCORD_PROVIDER = 'discord';
const DEFAULT_VANGUARD_API_KEY_HEADER = 'X-Vanguard-Api-Key';
const DEFAULT_VANGUARD_INSTANCE_HEADER = 'X-Vanguard-Instance-Id';
const VALID_GUARD_PRESETS = new Set(['off', 'relaxed', 'balanced', 'strict', 'siege']);

const sanitizeText = (value, maxLength = 120) => String(value || '').trim().slice(0, maxLength);

const parseBoolean = (value, fallback = false) => {
  if (value === undefined || value === null || value === '') return fallback;

  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
};

const parseCsv = (value, maxItemLength = 120) =>
  Array.from(
    new Set(
      String(value || '')
        .split(',')
        .map((entry) => sanitizeText(entry, maxItemLength))
        .filter(Boolean)
    )
  );

const normalizeSnowflake = (value) => {
  const candidate = sanitizeText(value, 32);
  return /^\d{5,32}$/.test(candidate) ? candidate : '';
};

const parseSnowflakes = (value) =>
  parseCsv(value, 32)
    .map((entry) => normalizeSnowflake(entry))
    .filter(Boolean);

const readApiKeys = () =>
  Array.from(
    new Set(
      [
        ...parseCsv(process.env.VANGUARD_API_KEYS, 512),
        sanitizeText(process.env.VANGUARD_API_KEY, 512),
      ].filter(Boolean)
    )
  );

const readGuardPresets = () =>
  parseCsv(process.env.VANGUARD_ENTITLEMENT_GUARD_PRESETS, 24)
    .map((preset) => preset.toLowerCase())
    .filter((preset) => VALID_GUARD_PRESETS.has(preset));

const getVanguardConfig = () => {
  const apiKeys = readApiKeys();
  const licenseAuthorized = parseBoolean(process.env.VANGUARD_LICENSE_AUTHORIZED, true);

  return {
    apiKeyHeader:
      sanitizeText(process.env.VANGUARD_API_KEY_HEADER, 64) || DEFAULT_VANGUARD_API_KEY_HEADER,
    instanceHeader:
      sanitizeText(process.env.VANGUARD_INSTANCE_HEADER, 64) || DEFAULT_VANGUARD_INSTANCE_HEADER,
    apiKeys,
    configured: apiKeys.length > 0,
    licenseAuthorized,
    licenseReason:
      sanitizeText(process.env.VANGUARD_LICENSE_REASON, 240) ||
      (licenseAuthorized ? 'active license' : 'license blocked'),
    allowedGuildIds: parseSnowflakes(process.env.VANGUARD_ALLOWED_GUILD_IDS),
    entitlements: {
      ai: parseBoolean(process.env.VANGUARD_ENTITLEMENT_AI, false),
      advancedVotes: parseBoolean(process.env.VANGUARD_ENTITLEMENT_ADVANCED_VOTES, false),
      guardPresets: readGuardPresets(),
    },
  };
};

const getStoredOauthIdentities = (user) =>
  Array.isArray(user?.oauthIdentities) ? user.oauthIdentities : [];

const findDiscordOauthIdentity = (user) =>
  getStoredOauthIdentities(user).find(
    (identity) => sanitizeText(identity?.provider, 40).toLowerCase() === DISCORD_PROVIDER
  ) || null;

const getVanguardFlags = (user) => ({
  trusted: Boolean(user?.integrations?.vanguard?.trusted),
  staff: Boolean(user?.integrations?.vanguard?.staff),
  flagged: Boolean(user?.integrations?.vanguard?.flagged),
  bannedFromAi: Boolean(user?.integrations?.vanguard?.aiDenied),
  flagReason: sanitizeText(user?.integrations?.vanguard?.flagReason, 240),
  flaggedAt: user?.integrations?.vanguard?.flaggedAt || null,
});

const ensureVanguardState = (user) => {
  const integrations =
    user?.integrations && typeof user.integrations === 'object' ? user.integrations : {};
  const state =
    integrations.vanguard && typeof integrations.vanguard === 'object'
      ? integrations.vanguard
      : {};

  user.integrations = integrations;
  user.integrations.vanguard = {
    trusted: Boolean(state.trusted),
    staff: Boolean(state.staff),
    flagged: Boolean(state.flagged),
    aiDenied: Boolean(state.aiDenied),
    flagReason: sanitizeText(state.flagReason, 240),
    flaggedAt: state.flaggedAt || null,
  };

  return user.integrations.vanguard;
};

const buildVanguardAccountState = (user) => {
  const discordIdentity = findDiscordOauthIdentity(user);
  const flags = getVanguardFlags(user);

  return {
    linkedDiscord: Boolean(discordIdentity?.providerUserId),
    discordUserId: sanitizeText(discordIdentity?.providerUserId, 160),
    linkedAt: discordIdentity?.linkedAt || null,
    lastUsedAt: discordIdentity?.lastUsedAt || null,
    ...flags,
  };
};

const buildVanguardResolvedUser = (user) => {
  const discordIdentity = findDiscordOauthIdentity(user);

  return {
    userId: String(user?._id || ''),
    continentalId: String(user?._id || ''),
    username: getDisplayableUsername(user),
    displayName: sanitizeText(user?.displayName, 60) || 'User',
    verified: Boolean(user?.isVerified),
    discordLinked: Boolean(discordIdentity?.providerUserId),
    discordUserId: sanitizeText(discordIdentity?.providerUserId, 160),
    linkedAt: discordIdentity?.linkedAt || null,
    lastUsedAt: discordIdentity?.lastUsedAt || null,
    createdAt: user?.createdAt || null,
    updatedAt: user?.updatedAt || null,
  };
};

module.exports = {
  DISCORD_PROVIDER,
  sanitizeText,
  normalizeSnowflake,
  getVanguardConfig,
  findDiscordOauthIdentity,
  getVanguardFlags,
  ensureVanguardState,
  buildVanguardAccountState,
  buildVanguardResolvedUser,
};
