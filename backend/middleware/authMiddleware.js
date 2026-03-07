const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    console.log('❌ No token found in header');
    return res.status(401).json({ message: 'No token provided.' });
  }

  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { id: decoded.userId };
    next();
  } catch (err) {
    console.log('❌ Token invalid:', err.message);
    res.status(401).json({ message: 'Token invalid or expired.' });
  }
};

