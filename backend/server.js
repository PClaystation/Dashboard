require('dotenv').config();
const fs = require('fs');
const https = require('https');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/authRoutes');

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(express.json({ limit: '10kb' }));

app.use(cookieParser());

console.log("Current environment:", process.env.NODE_ENV);

const requiredEnv = ['MONGO_URI', 'JWT_SECRET', 'REFRESH_TOKEN_SECRET'];
const missingEnv = requiredEnv.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
  console.error(`Missing required env vars: ${missingEnv.join(', ')}`);
  process.exit(1);
}


const allowedOrigins = [
    'https://pclaystation.github.io',
    'http://localhost:5502',
    'http://127.0.0.1:5501',
    'http://127.0.0.1:5502',
    'http://127.0.0.1:5503',
    'http://127.0.0.1:5504',
    'http://127.0.0.1:5505',
    'http://127.0.0.1:5506',
];

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) {
      // allow non-browser requests like Postman
      return callback(null, true);
    }

    try {
      const url = new URL(origin);
      // Allow all localhost origins regardless of port
      if ((url.hostname === 'localhost' || url.hostname === '127.0.0.1')) {
        return callback(null, true);
      }

      // Otherwise, allow if in allowedOrigins
      if (allowedOrigins.indexOf(origin) !== -1) {
        return callback(null, true);
      }

      return callback(new Error('Not allowed by CORS'), false);
    } catch {
      // If origin is invalid, deny
      return callback(new Error('Invalid origin'), false);
    }
  },
  credentials: true,
}));

const rateLimitWindowMs = 15 * 60 * 1000;
const rateLimitMax = 100;
const rateLimitStore = new Map();

const getClientId = (req) => {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String(forwarded).split(',')[0].trim();
  return req.ip || 'unknown';
};

const rateLimiter = (req, res, next) => {
  const key = getClientId(req);
  const now = Date.now();
  const entry = rateLimitStore.get(key);

  if (!entry || now - entry.start > rateLimitWindowMs) {
    rateLimitStore.set(key, { start: now, count: 1 });
    return next();
  }

  if (entry.count >= rateLimitMax) {
    return res.status(429).json({ message: 'Too many requests. Try again later.' });
  }

  entry.count += 1;
  return next();
};


mongoose.set('bufferCommands', false);

const connectToDatabase = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB connected');
  } catch (err) {
    console.error('MongoDB connection failed:', err);
    process.exit(1);
  }
};

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

app.use((req, res, next) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ message: 'Database unavailable. Try again shortly.' });
  }
  return next();
});

app.use('/api/auth', rateLimiter, authRoutes);

const PORT = process.env.PORT || 5000;

const startServer = async () => {
  await connectToDatabase();

  const keyPath = process.env.HTTPS_KEY_PATH || '/etc/letsencrypt/live/mpmc.ddns.net/privkey.pem';
  const certPath = process.env.HTTPS_CERT_PATH || '/etc/letsencrypt/live/mpmc.ddns.net/fullchain.pem';

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    const privateKey = fs.readFileSync(keyPath, 'utf8');
    const certificate = fs.readFileSync(certPath, 'utf8');
    const credentials = { key: privateKey, cert: certificate };

    https.createServer(credentials, app).listen(PORT, () => {
      console.log(`Auth service HTTPS running on port ${PORT}`);
    });
  } else {
    app.listen(PORT, () => {
      console.log(`Auth service HTTP running on port ${PORT}`);
    });
  }
};

startServer();
