const User = require('../models/User');

const normalizeCredentialId = (value) => String(value || '').trim().slice(0, 512);

const normalizePasskeyList = (passkeys = []) => {
  const normalized = [];
  const seen = new Set();
  let removed = 0;

  for (const passkey of Array.isArray(passkeys) ? passkeys : []) {
    const credentialId = normalizeCredentialId(passkey?.credentialId);
    if (!credentialId || seen.has(credentialId)) {
      removed += 1;
      continue;
    }

    seen.add(credentialId);
    const serializedPasskey =
      typeof passkey?.toObject === 'function' ? passkey.toObject() : { ...passkey };
    normalized.push({
      ...serializedPasskey,
      credentialId,
    });
  }

  return {
    passkeys: normalized,
    removed,
  };
};

const dedupePasskeysAcrossUsers = async ({ logger = console } = {}) => {
  let scanned = 0;
  let updated = 0;
  let removed = 0;
  const owners = new Map();

  const cursor = User.find({ 'security.passkeys.0': { $exists: true } })
    .sort({ _id: 1 })
    .cursor();

  for await (const user of cursor) {
    scanned += 1;

    const currentPasskeys = Array.isArray(user?.security?.passkeys)
      ? user.security.passkeys
      : [];
    const normalized = normalizePasskeyList(currentPasskeys);
    const nextPasskeys = [];
    let changed = normalized.removed > 0;
    removed += normalized.removed;

    for (const passkey of normalized.passkeys) {
      const credentialId = normalizeCredentialId(passkey?.credentialId);
      const ownerId = owners.get(credentialId);

      if (ownerId && ownerId !== String(user._id)) {
        removed += 1;
        changed = true;
        continue;
      }

      owners.set(credentialId, String(user._id));
      nextPasskeys.push(passkey);
    }

    if (!changed) {
      continue;
    }

    user.security.passkeys = nextPasskeys;
    await user.save();
    updated += 1;
  }

  const message = `Passkey hardening complete. Scanned ${scanned} users, updated ${updated}, removed ${removed} duplicate or invalid passkeys.`;
  if (typeof logger?.info === 'function') {
    logger.info(message);
  } else if (typeof logger?.log === 'function') {
    logger.log(message);
  }

  return { scanned, updated, removed };
};

module.exports = {
  dedupePasskeysAcrossUsers,
  normalizeCredentialId,
  normalizePasskeyList,
};
