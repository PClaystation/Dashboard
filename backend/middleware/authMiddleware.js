const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async (req, res, next) => {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'Authorization token required.' });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
    });
  } catch (err) {
    return res.status(401).json({ message: 'Token invalid or expired.' });
  }

  if (!decoded?.userId) {
    return res.status(401).json({ message: 'Invalid token payload.' });
  }

  try {
    const user = await User.findById(decoded.userId).select('_id refreshTokenVersion refreshSessions');
    if (!user) {
      return res.status(401).json({ message: 'User not found for token.' });
    }

    if (user.refreshTokenVersion !== decoded.tokenVersion) {
      return res.status(401).json({ message: 'Session is no longer valid.' });
    }

    const sid = String(decoded.sid || '').trim();
    if (sid) {
      const hasActiveSession = Array.isArray(user.refreshSessions)
        ? user.refreshSessions.some((session) => String(session?.sid || '').trim() === sid)
        : false;

      if (!hasActiveSession) {
        return res.status(401).json({ message: 'Session has been revoked.' });
      }
    }

    req.user = {
      id: String(user._id),
      tokenVersion: decoded.tokenVersion,
      sid: sid || null,
    };

    return next();
  } catch (err) {
    return next(err);
  }
};
