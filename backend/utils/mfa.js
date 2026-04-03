const crypto = require('crypto');
const QRCode = require('qrcode');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const DEFAULT_PERIOD_SECONDS = 30;
const DEFAULT_DIGITS = 6;

const encodeBase32 = (buffer) => {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
};

const decodeBase32 = (value) => {
  const normalized = String(value || '')
    .toUpperCase()
    .replace(/=+$/g, '')
    .replace(/[^A-Z2-7]/g, '');

  let bits = 0;
  let aggregate = 0;
  const bytes = [];

  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) continue;

    aggregate = (aggregate << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bytes.push((aggregate >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
};

const generateMfaSecret = (size = 20) => encodeBase32(crypto.randomBytes(size));

const hotp = ({ secret, counter, digits = DEFAULT_DIGITS }) => {
  const secretBuffer = decodeBase32(secret);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', secretBuffer).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(binary % 10 ** digits).padStart(digits, '0');
};

const totp = ({ secret, digits = DEFAULT_DIGITS, period = DEFAULT_PERIOD_SECONDS, timestamp = Date.now() }) => {
  const counter = Math.floor(timestamp / 1000 / period);
  return hotp({ secret, counter, digits });
};

const verifyTotp = ({
  secret,
  token,
  digits = DEFAULT_DIGITS,
  period = DEFAULT_PERIOD_SECONDS,
  timestamp = Date.now(),
  window = 1,
}) => {
  const normalizedToken = String(token || '').replace(/\s+/g, '');
  if (!/^\d{6,8}$/.test(normalizedToken) || !secret) return false;

  const currentCounter = Math.floor(timestamp / 1000 / period);
  for (let offset = -window; offset <= window; offset += 1) {
    const expected = hotp({
      secret,
      counter: currentCounter + offset,
      digits,
    });

    if (expected === normalizedToken) {
      return true;
    }
  }

  return false;
};

const buildOtpAuthUrl = ({ secret, accountName, issuer = 'Continental ID' }) => {
  const label = `${issuer}:${accountName || 'user'}`;
  const url = new URL(`otpauth://totp/${encodeURIComponent(label)}`);
  url.searchParams.set('secret', secret);
  url.searchParams.set('issuer', issuer);
  url.searchParams.set('algorithm', 'SHA1');
  url.searchParams.set('digits', String(DEFAULT_DIGITS));
  url.searchParams.set('period', String(DEFAULT_PERIOD_SECONDS));
  return url.toString();
};

const buildOtpAuthQrDataUrl = async (otpAuthUrl) => {
  if (!otpAuthUrl) return '';

  return QRCode.toDataURL(otpAuthUrl, {
    errorCorrectionLevel: 'M',
    margin: 1,
    width: 220,
  });
};

const generateBackupCodes = (count = 8) =>
  Array.from({ length: count }, () =>
    `${crypto.randomBytes(2).toString('hex')}-${crypto.randomBytes(2).toString('hex')}`.toUpperCase()
  );

module.exports = {
  buildOtpAuthQrDataUrl,
  buildOtpAuthUrl,
  generateBackupCodes,
  generateMfaSecret,
  totp,
  verifyTotp,
};
