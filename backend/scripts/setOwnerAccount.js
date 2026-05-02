#!/usr/bin/env node
require('dotenv').config();

const mongoose = require('mongoose');
const User = require('../models/User');

const usage = () => {
  console.log('Usage: node scripts/setOwnerAccount.js <email> [--demote]');
};

const run = async () => {
  const [, , emailArg, modeArg] = process.argv;
  const email = String(emailArg || '').trim().toLowerCase();
  const demote = String(modeArg || '').trim() === '--demote';

  if (!email) {
    usage();
    process.exitCode = 1;
    return;
  }

  if (!process.env.MONGO_URI) {
    throw new Error('MONGO_URI is required.');
  }

  await mongoose.connect(process.env.MONGO_URI, {
    maxPoolSize: 5,
    serverSelectionTimeoutMS: 5000,
  });

  try {
    const user = await User.findOne({ email });
    if (!user) {
      throw new Error(`No user found for ${email}.`);
    }

    user.accountRole = demote ? 'user' : 'owner';
    if (!demote) {
      user.accountStatus = 'active';
    }
    await user.save();

    console.log(
      `${demote ? 'Demoted' : 'Promoted'} ${email} to ${user.accountRole} (status: ${user.accountStatus}).`
    );
  } finally {
    await mongoose.disconnect();
  }
};

run().catch((err) => {
  console.error(err.message || err);
  process.exitCode = 1;
});
