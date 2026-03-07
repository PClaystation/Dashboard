const nodemailer = require('nodemailer');

let cachedTransporter = null;

const hasSmtpConfig = () => {
  return Boolean(process.env.EMAIL_HOST && process.env.EMAIL_PORT && process.env.EMAIL_USER && process.env.EMAIL_PASS);
};

const hasServiceConfig = () => {
  return Boolean(process.env.EMAIL_SERVICE && process.env.EMAIL_USER && process.env.EMAIL_PASS);
};

const createTransport = () => {
  if (hasSmtpConfig()) {
    return nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: Number(process.env.EMAIL_PORT),
      secure: String(process.env.EMAIL_SECURE || 'false') === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
  }

  if (hasServiceConfig()) {
    return nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
  }

  return null;
};

const getTransporter = () => {
  if (!cachedTransporter) {
    cachedTransporter = createTransport();
  }
  return cachedTransporter;
};

async function sendEmail(to, subject, html) {
  if (!to) {
    throw new Error('Email recipient is required.');
  }

  const transporter = getTransporter();

  if (!transporter) {
    console.warn('Email provider is not configured; skipping sendEmail call.');
    return {
      skipped: true,
      accepted: [],
      rejected: [to],
    };
  }

  const fromAddress = process.env.EMAIL_FROM || process.env.EMAIL_USER;

  return transporter.sendMail({
    from: `"Continental ID" <${fromAddress}>`,
    to,
    subject,
    html,
  });
}

module.exports = sendEmail;
