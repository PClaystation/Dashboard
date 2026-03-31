const AUTH_CONFIG = window.__AUTH_CONFIG__ || {};
const LOCAL_HOSTS = new Set(AUTH_CONFIG.localHosts || ['localhost', '127.0.0.1']);
const TRUSTED_API_ORIGINS = new Set(AUTH_CONFIG.trustedApiOrigins || []);
const HOSTED_API_BASE_URL =
  AUTH_CONFIG.hostedApiBaseUrl || 'https://grimoire.continental-hub.com';
const params = new URLSearchParams(window.location.search);
const token = String(params.get('token') || '').trim();

function trimTrailingSlash(value) {
  return String(value || '').replace(/\/+$/, '');
}

function isTrustedApiOrigin(origin) {
  if (!origin) return false;

  try {
    const parsed = new URL(origin);
    if (LOCAL_HOSTS.has(parsed.hostname)) return true;
    return TRUSTED_API_ORIGINS.has(parsed.origin);
  } catch {
    return false;
  }
}

function resolveTrustedApiBaseUrl(value) {
  if (!value) return '';

  try {
    const resolved = new URL(value, window.location.origin);
    return isTrustedApiOrigin(resolved.origin) ? trimTrailingSlash(resolved.origin) : '';
  } catch {
    return '';
  }
}

function getDefaultApiBaseUrl() {
  if (LOCAL_HOSTS.has(window.location.hostname)) {
    return 'http://localhost:5000';
  }

  if (
    window.location.hostname === 'dashboard.continental-hub.com' ||
    window.location.hostname === 'login.continental-hub.com'
  ) {
    return HOSTED_API_BASE_URL;
  }

  return window.location.origin;
}

const API_BASE_URL =
  resolveTrustedApiBaseUrl(params.get('apiBaseUrl')) ||
  resolveTrustedApiBaseUrl(window.__API_BASE_URL__) ||
  trimTrailingSlash(getDefaultApiBaseUrl());
const AUTH_API_BASE = `${API_BASE_URL}/api/auth`;
const heading = document.getElementById('heading');
const description = document.getElementById('description');
const status = document.getElementById('status');
const loginLink = document.getElementById('login-link');

function setStatus(message, tone) {
  status.textContent = message;
  status.dataset.status = tone;
  status.classList.toggle('is-visible', Boolean(message));
}

const popupUrl = new URL('popup.html', window.location.href);
if (params.get('origin')) popupUrl.searchParams.set('origin', params.get('origin'));
if (params.get('redirect')) popupUrl.searchParams.set('redirect', params.get('redirect'));
if (params.get('apiBaseUrl')) popupUrl.searchParams.set('apiBaseUrl', params.get('apiBaseUrl'));
loginLink.href = popupUrl.toString();

async function verify() {
  if (!token) {
    heading.textContent = 'Verification link missing';
    description.textContent = 'No verification token was found in the URL.';
    setStatus('Use the link from your verification email.', 'error');
    return;
  }

  setStatus('Checking your verification token...', 'info');

  try {
    const verifyUrl = `${AUTH_API_BASE}/verify-email?token=${encodeURIComponent(token)}`;
    const res = await fetch(verifyUrl, { method: 'GET', credentials: 'include' });
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      heading.textContent = 'Verification failed';
      description.textContent = 'The verification link could not be accepted.';
      setStatus(data.message || 'Invalid or expired verification token.', 'error');
      return;
    }

    heading.textContent = 'Email verified';
    description.textContent = 'Your email has been confirmed and the account is ready for sign-in.';
    setStatus('Verification successful. You can now log in.', 'success');
  } catch (error) {
    heading.textContent = 'Verification failed';
    description.textContent = 'The request could not be completed.';
    setStatus(error.message || 'Network error while verifying email.', 'error');
  }
}

verify();
