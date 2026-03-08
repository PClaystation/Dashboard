const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'Authorization token required.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded?.userId) {
      return res.status(401).json({ message: 'Invalid token payload.' });
    }

    req.user = {
      id: decoded.userId,
      tokenVersion: decoded.tokenVersion,
      sid: decoded.sid || null,
    };

    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Token invalid or expired.' });
  }
};
