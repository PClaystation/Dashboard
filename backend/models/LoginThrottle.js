const mongoose = require('mongoose');

const loginThrottleSchema = new mongoose.Schema(
  {
    key: { type: String, required: true, unique: true, index: true },
    count: { type: Number, default: 0 },
    windowStartedAt: { type: Date, default: Date.now },
    blockedUntil: { type: Date, default: null },
    expiresAt: { type: Date, required: true, index: { expires: 0 } },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model('LoginThrottle', loginThrottleSchema);
