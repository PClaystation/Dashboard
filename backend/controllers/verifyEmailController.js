const User = require('../models/User');

exports.verifyEmail = async (req, res) => {
  const token = String(req.query.token || '').trim();

  if (!token) {
    return res.status(400).json({ message: 'Verification token is required.' });
  }

  try {
    // Find user with valid, unexpired verification token
    const user = await User.findOne({
      verificationToken: token,
      verificationTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification link.' });
    }

    // Mark user as verified and remove the token fields
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;

    await user.save();

    return res.status(200).json({ message: 'Email verified successfully. You can now log in.' });
  } catch (err) {
    console.error('Email verification error:', err);
    return res.status(500).json({ message: 'Email verification failed.' });
  }
};
