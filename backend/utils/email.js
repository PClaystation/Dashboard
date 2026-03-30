const { Resend } = require('resend');

let cachedClient = null;

const hasResendConfig = () => {
  return Boolean(process.env.RESEND_API_KEY && process.env.EMAIL_FROM);
};

const getResendClient = () => {
  if (!hasResendConfig()) {
    return null;
  }

  if (!cachedClient) {
    cachedClient = new Resend(process.env.RESEND_API_KEY);
  }

  return cachedClient;
};

const buildFromHeader = () => {
  const fromAddress = String(process.env.EMAIL_FROM || '').trim();
  const fromName = String(process.env.EMAIL_FROM_NAME || 'Continental ID').trim();

  if (!fromAddress) {
    return '';
  }

  if (fromAddress.includes('<')) {
    return fromAddress;
  }

  return fromName ? `${fromName} <${fromAddress}>` : fromAddress;
};

async function sendEmail({ to, subject, html, text, replyTo } = {}) {
  if (!to) {
    throw new Error('Email recipient is required.');
  }

  const resend = getResendClient();
  const from = buildFromHeader();

  if (!resend || !from) {
    console.warn('Resend email is not configured; skipping sendEmail call.');
    return {
      skipped: true,
      reason: 'email_not_configured',
    };
  }

  const recipients = Array.isArray(to) ? to : [to];
  const payload = {
    from,
    to: recipients,
    subject,
    html,
  };

  const plainText = String(text || '').trim();
  if (plainText) {
    payload.text = plainText;
  }

  const resolvedReplyTo = String(replyTo || process.env.EMAIL_REPLY_TO || '').trim();
  if (resolvedReplyTo) {
    payload.replyTo = resolvedReplyTo;
  }

  const { data, error } = await resend.emails.send(payload);
  if (error) {
    const err = new Error(error.message || 'Resend email request failed.');
    err.cause = error;
    throw err;
  }

  return {
    skipped: false,
    id: String(data?.id || ''),
    data,
  };
}

module.exports = sendEmail;
