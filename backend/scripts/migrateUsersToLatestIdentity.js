require('dotenv').config();

const mongoose = require('mongoose');
const { migrateUsersToLatestIdentity } = require('../utils/userIdentity');

const mongoUri = process.env.MONGO_URI;

if (!mongoUri) {
  console.error('MONGO_URI is required to run the user migration.');
  process.exit(1);
}

const run = async () => {
  try {
    await mongoose.connect(mongoUri, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
    });

    const result = await migrateUsersToLatestIdentity({ logger: console });
    console.log(`Migration finished. Scanned ${result.scanned} users, updated ${result.updated}.`);
    await mongoose.connection.close();
    process.exit(0);
  } catch (err) {
    console.error('User identity migration failed:', err);
    try {
      await mongoose.connection.close();
    } catch {
      // ignore shutdown errors after migration failure
    }
    process.exit(1);
  }
};

run();
