const jwt = require('jsonwebtoken');

const TOKEN_ISSUER =
  String(process.env.TOKEN_ISSUER || process.env.APP_NAME || 'continental-id-auth').trim() ||
  'continental-id-auth';

const ACCESS_TOKEN_AUDIENCE = 'continental-id:access';
const REFRESH_TOKEN_AUDIENCE = 'continental-id:refresh';
const OAUTH_STATE_AUDIENCE = 'continental-id:oauth-state';
const WEBAUTHN_CHALLENGE_AUDIENCE = 'continental-id:webauthn-challenge';
const DEVICE_COOKIE_AUDIENCE = 'continental-id:device-cookie';

const signTypedJwt = ({
  secret,
  payload = {},
  expiresIn,
  audience,
  type,
  subject,
  jwtid,
} = {}) => {
  const options = {
    algorithm: 'HS256',
  };

  if (audience) options.audience = audience;
  if (expiresIn !== undefined) options.expiresIn = expiresIn;
  if (TOKEN_ISSUER) options.issuer = TOKEN_ISSUER;
  if (jwtid) options.jwtid = jwtid;
  if (subject) options.subject = subject;

  return jwt.sign(
    {
      type,
      ...payload,
    },
    secret,
    options
  );
};

const verifyTypedJwt = ({
  token,
  secret,
  audience,
  type,
  allowLegacy = false,
} = {}) => {
  let strictError = null;

  try {
    const payload = jwt.verify(token, secret, {
      algorithms: ['HS256'],
      audience,
      issuer: TOKEN_ISSUER,
    });

    if (type && payload?.type !== type) {
      throw new Error('Unexpected token type.');
    }

    return payload;
  } catch (err) {
    strictError = err;
  }

  if (!allowLegacy) {
    throw strictError;
  }

  const legacyPayload = jwt.verify(token, secret, {
    algorithms: ['HS256'],
  });

  if (legacyPayload?.aud || legacyPayload?.iss || legacyPayload?.type) {
    throw strictError;
  }

  if (type && legacyPayload?.type && legacyPayload.type !== type) {
    throw strictError;
  }

  return legacyPayload;
};

module.exports = {
  ACCESS_TOKEN_AUDIENCE,
  DEVICE_COOKIE_AUDIENCE,
  OAUTH_STATE_AUDIENCE,
  REFRESH_TOKEN_AUDIENCE,
  TOKEN_ISSUER,
  WEBAUTHN_CHALLENGE_AUDIENCE,
  signTypedJwt,
  verifyTypedJwt,
};
