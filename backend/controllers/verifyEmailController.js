const User = require('../models/User');
const { hashEmailVerificationToken } = require('../utils/emailVerification');

exports.verifyEmail = async (req, res) => {
  const token = String(req.query.token || '').trim();

  if (!token) {
    return res.status(400).json({ message: 'Verification token is required.' });
  }

  try {
    const hashedToken = hashEmailVerificationToken(token);
    const user = await User.findOne({
      verificationToken: hashedToken,
      verificationTokenExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification link.' });
    }

    user.isVerified = true;
    user.verificationToken = '';
    user.verificationTokenExpires = null;

    await user.save();

    return res.status(200).json({ message: 'Email verified successfully. You can now log in.' });
  } catch (err) {
    console.error('Email verification error:', err);
    return res.status(500).json({ message: 'Email verification failed.' });
  }
};
