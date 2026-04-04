const crypto = require('crypto');
const {
  getVanguardConfig,
  sanitizeText,
} = require('../utils/vanguardIntegration');

const secureCompare = (left, right) => {
  const leftBuffer = Buffer.from(String(left || ''), 'utf8');
  const rightBuffer = Buffer.from(String(right || ''), 'utf8');

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
};

module.exports = (req, res, next) => {
  const config = getVanguardConfig();
  if (!config.configured) {
    return res.status(503).json({
      message: 'Vanguard integration is not configured on this server.',
      requestId: req.requestId,
    });
  }

  const apiKey = sanitizeText(req.get(config.apiKeyHeader), 512);
  if (!apiKey) {
    return res.status(401).json({
      message: `Missing ${config.apiKeyHeader} header.`,
      requestId: req.requestId,
    });
  }

  const authenticated = config.apiKeys.some((candidate) => secureCompare(apiKey, candidate));
  if (!authenticated) {
    return res.status(401).json({
      message: 'Invalid Vanguard API key.',
      requestId: req.requestId,
    });
  }

  req.vanguardConfig = config;
  req.vanguardClient = {
    instanceId: sanitizeText(req.get(config.instanceHeader), 160),
  };

  return next();
};
