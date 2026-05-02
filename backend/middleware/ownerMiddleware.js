module.exports = (req, res, next) => {
  if (req.user?.isOwner) {
    return next();
  }

  return res.status(403).json({ message: 'Owner access required.' });
};
