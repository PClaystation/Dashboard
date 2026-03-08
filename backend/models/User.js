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

const refreshSessionSchema = new mongoose.Schema(
  {
    sid: { type: String, required: true },
    label: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now },
    lastUsedAt: { type: Date, default: Date.now },
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
    refreshSessions: {
      type: [refreshSessionSchema],
      default: [],
    },
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String, default: '' },
    verificationTokenExpires: { type: Date, default: null },
    lastLoginAt: { type: Date },
    lastLoginIp: { type: String, default: '' },
    recentLogins: {
      type: [loginEventSchema],
      default: [],
    },
    profile: {
      bio: { type: String, default: '', maxlength: 320 },
      location: { type: String, default: '', maxlength: 120 },
      website: { type: String, default: '', maxlength: 240 },
      timezone: { type: String, default: 'UTC', maxlength: 80 },
      language: { type: String, default: 'en', maxlength: 32 },
    },
    linkedAccounts: {
      google: { type: String, default: '' },
      facebook: { type: String, default: '' },
      github: { type: String, default: '' },
      twitter: { type: String, default: '' },
      linkedin: { type: String, default: '' },
      discord: { type: String, default: '' },
      apple: { type: String, default: '' },
      microsoft: { type: String, default: '' },
    },
    preferences: {
      profilePublic: { type: Boolean, default: true },
      searchable: { type: Boolean, default: true },
      notifications: {
        email: { type: Boolean, default: true },
        sms: { type: Boolean, default: false },
        push: { type: Boolean, default: true },
        weeklyDigest: { type: Boolean, default: true },
        security: { type: Boolean, default: true },
      },
      appearance: {
        theme: {
          type: String,
          enum: ['system', 'dawn', 'night', 'ocean'],
          default: 'system',
        },
        compactMode: { type: Boolean, default: false },
        reducedMotion: { type: Boolean, default: false },
        highContrast: { type: Boolean, default: false },
        dashboardDensity: {
          type: String,
          enum: ['comfortable', 'compact', 'spacious'],
          default: 'comfortable',
        },
      },
    },
    security: {
      twoFactorEnabled: { type: Boolean, default: false },
      loginAlerts: { type: Boolean, default: true },
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
