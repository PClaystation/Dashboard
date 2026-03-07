const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const loginEventSchema = new mongoose.Schema(
  {
    at: { type: Date, default: Date.now },
    ip: { type: String, default: '' },
    userAgent: { type: String, default: '' },
  },
  { _id: false }
);

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    displayName: {
      type: String,
      default: '',
      trim: true,
      maxlength: 60,
    },
    password: { type: String, required: true },
    refreshTokenVersion: { type: Number, default: 0 },
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String, default: '' },
    verificationTokenExpires: { type: Date, default: null },
    lastLoginAt: { type: Date },
    lastLoginIp: { type: String, default: '' },
    recentLogins: {
      type: [loginEventSchema],
      default: [],
    },
    linkedAccounts: {
      google: { type: String, default: '' },
      facebook: { type: String, default: '' },
      github: { type: String, default: '' },
      twitter: { type: String, default: '' },
    },
    preferences: {
      profilePublic: { type: Boolean, default: true },
      searchable: { type: Boolean, default: true },
      notifications: {
        email: { type: Boolean, default: true },
        sms: { type: Boolean, default: false },
        push: { type: Boolean, default: true },
      },
    },
    security: {
      twoFactorEnabled: { type: Boolean, default: false },
      passwordChangedAt: { type: Date, default: null },
    },
  },
  {
    timestamps: true,
  }
);

userSchema.pre('save', async function onSave(next) {
  if (!this.displayName && this.email) {
    const [localPart] = String(this.email).split('@');
    this.displayName = localPart || 'User';
  }

  if (!this.isModified('password')) {
    return next();
  }

  this.password = await bcrypt.hash(this.password, 10);
  this.security.passwordChangedAt = new Date();
  return next();
});

userSchema.methods.comparePassword = function comparePassword(candidate) {
  return bcrypt.compare(candidate, this.password);
};

module.exports = mongoose.model('User', userSchema);
