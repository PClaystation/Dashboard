const mongoose = require('mongoose');

const apiRateLimitBucketSchema = new mongoose.Schema(
  {
    key: { type: String, required: true, index: true },
    windowStart: { type: Date, required: true },
    count: { type: Number, default: 0 },
    expiresAt: { type: Date, required: true, index: { expires: 0 } },
  },
  {
    timestamps: true,
  }
);

apiRateLimitBucketSchema.index({ key: 1, windowStart: 1 }, { unique: true });

module.exports = mongoose.model('ApiRateLimitBucket', apiRateLimitBucketSchema);
