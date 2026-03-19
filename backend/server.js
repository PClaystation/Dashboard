require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/authRoutes');
const grimoireRoutes = require('./routes/grimoireRoutes');

const app = express();

const REQUIRED_ALLOWED_ORIGINS = [
  'https://pclaystation.github.io',
  'https://dashboard.continental-hub.com',
  'https://grimoire.continental-hub.com',
  'https://login.continental-hub.com',
  'https://mpmc.ddns.net',
];

const allowedOriginsFromEnv = String(process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

const config = {
  appName: process.env.APP_NAME || 'continental-id-auth',
  nodeEnv: process.env.NODE_ENV || 'development',
  host: process.env.HOST || '127.0.0.1',
  port: Number(process.env.PORT) || 5000,
  mongoUri: process.env.MONGO_URI,
  jwtSecret: process.env.JWT_SECRET,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET,
  allowedOrigins: Array.from(new Set([...REQUIRED_ALLOWED_ORIGINS, ...allowedOriginsFromEnv])),
  rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  rateLimitMax: Number(process.env.RATE_LIMIT_MAX) || 180,
  httpsKeyPath:
    process.env.HTTPS_KEY_PATH || '/etc/letsencrypt/live/mpmc.ddns.net/privkey.pem',
  httpsCertPath:
    process.env.HTTPS_CERT_PATH || '/etc/letsencrypt/live/mpmc.ddns.net/fullchain.pem',
};
const isProduction = config.nodeEnv === 'production';
const allowLocalDevOrigins =
  !isProduction || String(process.env.ALLOW_LOCALHOST_ORIGINS || 'false') === 'true';

const requiredEnv = ['MONGO_URI', 'JWT_SECRET', 'REFRESH_TOKEN_SECRET'];
const missingEnv = requiredEnv.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
  console.error(`Missing required env vars: ${missingEnv.join(', ')}`);
  process.exit(1);
}

const hasStrongSecret = (value) => {
  const secret = String(value || '').trim();
  if (secret.length < 32) return false;
  if (secret.includes('replace-with-a-long-random-secret')) return false;
  if (secret.includes('replace-with-a-second-long-random-secret')) return false;
  return true;
};

const allowedOriginsSet = new Set(config.allowedOrigins);

if (isProduction) {
  if (!hasStrongSecret(config.jwtSecret)) {
    console.error('JWT_SECRET must be set to a strong random value in production.');
    process.exit(1);
  }

  if (!hasStrongSecret(config.refreshTokenSecret)) {
    console.error('REFRESH_TOKEN_SECRET must be set to a strong random value in production.');
    process.exit(1);
  }

  if (allowedOriginsSet.size === 0) {
    console.error('ALLOWED_ORIGINS must include at least one trusted frontend origin in production.');
    process.exit(1);
  }
}
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use((req, res, next) => {
  const requestId = crypto.randomUUID();
  req.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);
  return next();
});

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false, limit: '200kb' }));
app.use(cookieParser());

const isAllowedOrigin = (origin) => {
  if (!origin) return true;

  const normalizedOrigin = String(origin).trim().replace(/\/+$/, '');

  try {
    const url = new URL(normalizedOrigin);
    if (
      allowLocalDevOrigins &&
      (url.hostname === 'localhost' || url.hostname === '127.0.0.1')
    ) {
      return true;
    }
  } catch {
    return false;
  }

  return allowedOriginsSet.has(normalizedOrigin);
};

app.use(
  cors({
    origin(origin, callback) {
      if (isAllowedOrigin(origin)) {
        return callback(null, true);
      }
      console.warn(`CORS denied origin: ${origin || 'unknown'}`);
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

const rateLimitStore = new Map();

const getClientKey = (req) => {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return String(forwarded).split(',')[0].trim();
  }
  return req.ip || 'unknown';
};

const apiRateLimiter = (req, res, next) => {
  const now = Date.now();
  const key = getClientKey(req);
  const entry = rateLimitStore.get(key);

  if (!entry || now - entry.start > config.rateLimitWindowMs) {
    rateLimitStore.set(key, { start: now, count: 1 });
    return next();
  }

  if (entry.count >= config.rateLimitMax) {
    return res.status(429).json({
      message: 'Too many requests. Please try again later.',
      requestId: req.requestId,
    });
  }

  entry.count += 1;
  return next();
};

const staleBucketCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore.entries()) {
    if (now - entry.start > config.rateLimitWindowMs) {
      rateLimitStore.delete(key);
    }
  }
}, Math.max(30_000, Math.floor(config.rateLimitWindowMs / 2)));

staleBucketCleanupInterval.unref();

mongoose.set('bufferCommands', false);

const connectToDatabase = async () => {
  await mongoose.connect(config.mongoUri, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
  });
};

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

app.get('/api/health', (req, res) => {
  const dbConnected = mongoose.connection.readyState === 1;
  const status = dbConnected ? 200 : 503;

  return res.status(status).json({
    service: config.appName,
    status: dbConnected ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
  });
});

app.use('/api', apiRateLimiter);

app.use((req, res, next) => {
  if (req.path === '/api/health') {
    return next();
  }

  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({
      message: 'Database unavailable. Try again shortly.',
      requestId: req.requestId,
    });
  }

  return next();
});

app.use('/api/auth', authRoutes);
app.use('/api/grimoire', grimoireRoutes);

app.use('/api', (req, res) => {
  return res.status(404).json({
    message: 'API route not found.',
    requestId: req.requestId,
  });
});

app.use((err, req, res, next) => {
  if (err?.message === 'Not allowed by CORS') {
    return res.status(403).json({
      message: 'CORS origin denied.',
      requestId: req.requestId,
    });
  }

  console.error(`[${req.requestId}]`, err);
  return res.status(500).json({
    message: 'Internal server error.',
    requestId: req.requestId,
  });
});

let server;

const startServer = async () => {
  try {
    await connectToDatabase();
    console.log('MongoDB connected');
  } catch (err) {
    console.error('MongoDB connection failed:', err);
    process.exit(1);
  }

  const hasHttpsFiles = fs.existsSync(config.httpsKeyPath) && fs.existsSync(config.httpsCertPath);

  if (hasHttpsFiles) {
    const privateKey = fs.readFileSync(config.httpsKeyPath, 'utf8');
    const certificate = fs.readFileSync(config.httpsCertPath, 'utf8');
    server = https.createServer({ key: privateKey, cert: certificate }, app);
    server.listen(config.port, config.host, () => {
      console.log(`Auth service HTTPS running on https://${config.host}:${config.port}`);
    });
    return;
  }

  server = http.createServer(app);
  server.listen(config.port, config.host, () => {
    console.log(`Auth service HTTP running on http://${config.host}:${config.port}`);
  });
};

const shutdown = async (signal) => {
  console.log(`Received ${signal}. Shutting down gracefully...`);

  clearInterval(staleBucketCleanupInterval);

  try {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }

    await mongoose.connection.close();
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

startServer();
