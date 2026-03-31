const AUTH_CONFIG = window.__AUTH_CONFIG__ || {};
const LOCAL_HOSTS = new Set(AUTH_CONFIG.localHosts || ['localhost', '127.0.0.1']);
const TRUSTED_APP_ORIGINS = new Set(AUTH_CONFIG.trustedAppOrigins || []);
const TRUSTED_API_ORIGINS = new Set(AUTH_CONFIG.trustedApiOrigins || []);
const DEFAULT_DASHBOARD_ORIGIN =
  AUTH_CONFIG.defaultDashboardOrigin || 'https://dashboard.continental-hub.com';
const HOSTED_API_BASE_URL =
  AUTH_CONFIG.hostedApiBaseUrl || 'https://mpmc.ddns.net';
const USERNAME_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{1,28}[A-Za-z0-9])?$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const params = new URLSearchParams(window.location.search);

const trimTrailingSlash = (value) => String(value || '').replace(/\/+$/, '');
const safeText = (value) => String(value || '').trim();
const HOSTED_APP_HOSTS = new Set(
  [...TRUSTED_APP_ORIGINS]
    .map((origin) => {
      try {
        return new URL(origin).hostname;
      } catch {
        return '';
      }
    })
    .filter(Boolean)
);
const statusBanner = document.getElementById('status-banner');
const loginToggle = document.getElementById('login-toggle');
const registerToggle = document.getElementById('register-toggle');
const loginPanel = document.getElementById('login-panel');
const registerPanel = document.getElementById('register-panel');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const loginBtn = document.getElementById('login-btn');
const registerBtn = document.getElementById('register-btn');
const loginPrimaryFields = document.getElementById('login-primary-fields');
const loginMfaStep = document.getElementById('login-mfa-step');
const loginMfaCopy = document.getElementById('login-mfa-copy');
const loginMfaCode = document.getElementById('login-mfa-code');
const loginBackupCode = document.getElementById('login-backup-code');
const loginMfaBackBtn = document.getElementById('login-mfa-back-btn');
const loginMfaHelper = document.getElementById('login-mfa-helper');
const mfaMethodTotp = document.getElementById('mfa-method-totp');
const mfaMethodBackup = document.getElementById('mfa-method-backup');
const mfaPanelTotp = document.getElementById('mfa-panel-totp');
const mfaPanelBackup = document.getElementById('mfa-panel-backup');
const forgotPasswordLink = document.getElementById('forgot-password-link');
const resendVerificationBtn = document.getElementById('resend-verification-btn');
const verificationResetBtn = document.getElementById('verification-reset-btn');
const verificationActions = document.getElementById('verification-actions');
const openFullPageLink = document.getElementById('open-full-page-link');
const loginIdentifierInput = document.getElementById('login-identifier');
const loginPasswordInput = document.getElementById('login-password');
const registerUsernameInput = document.getElementById('register-username');
const registerDisplayNameInput = document.getElementById('register-display-name');
const registerEmailInput = document.getElementById('register-email');
const registerPasswordInput = document.getElementById('register-password');
const registerConfirmPasswordInput = document.getElementById('register-confirm-password');
const registerPasswordStrength = document.getElementById('register-password-strength');
const registerPasswordStrengthFill = document.getElementById('register-password-strength-fill');
const registerPasswordStrengthCopy = document.getElementById('register-password-strength-copy');

let awaitingMfa = false;
let activeMfaMethod = 'totp';
let pendingVerificationIdentifier = '';
let loginCooldownTimer = 0;
let loginCooldownUntil = 0;

const isTrustedApiOrigin = (origin) => {
  if (!origin) return false;

  try {
    const parsed = new URL(origin);
    if (LOCAL_HOSTS.has(parsed.hostname)) return true;
    return TRUSTED_API_ORIGINS.has(parsed.origin);
  } catch {
    return false;
  }
};

const resolveTrustedApiBaseUrl = (value) => {
  if (!value) return '';

  try {
    const resolved = new URL(value, window.location.origin);
    return isTrustedApiOrigin(resolved.origin) ? trimTrailingSlash(resolved.origin) : '';
  } catch {
    return '';
  }
};

const getDefaultApiBaseUrl = () => {
  if (LOCAL_HOSTS.has(window.location.hostname)) {
    return 'http://localhost:5000';
  }

  if (HOSTED_APP_HOSTS.has(window.location.hostname)) {
    return HOSTED_API_BASE_URL;
  }

  return window.location.origin;
};

const API_BASE_URL =
  resolveTrustedApiBaseUrl(params.get('apiBaseUrl')) ||
  resolveTrustedApiBaseUrl(window.__API_BASE_URL__) ||
  trimTrailingSlash(getDefaultApiBaseUrl());
const AUTH_API_BASE = `${API_BASE_URL}/api/auth`;

const isTrustedAppOrigin = (origin) => {
  if (!origin) return false;

  try {
    const parsed = new URL(origin);
    if (LOCAL_HOSTS.has(parsed.hostname)) return true;
    return TRUSTED_APP_ORIGINS.has(parsed.origin);
  } catch {
    return false;
  }
};

const resolveTrustedOrigin = (value) => {
  if (!value) return '';

  try {
    const origin = new URL(value).origin;
    return isTrustedAppOrigin(origin) ? origin : '';
  } catch {
    return '';
  }
};

const targetOrigin =
  resolveTrustedOrigin(params.get('origin')) || resolveTrustedOrigin(document.referrer) || '';

const resolveRedirectUrl = (value, fallbackOrigin) => {
  const safeFallbackOrigin = isTrustedAppOrigin(fallbackOrigin)
    ? fallbackOrigin
    : DEFAULT_DASHBOARD_ORIGIN;

  try {
    const resolved = new URL(value || '/', safeFallbackOrigin);
    if (!isTrustedAppOrigin(resolved.origin)) {
      return new URL('/', safeFallbackOrigin).toString();
    }
    return resolved.toString();
  } catch {
    return new URL('/', safeFallbackOrigin).toString();
  }
};

const redirectUrl = resolveRedirectUrl(params.get('redirect'), targetOrigin);

const setStatus = (message, tone = 'error') => {
  const text = safeText(message);
  statusBanner.textContent = text;
  statusBanner.dataset.status = tone;
  statusBanner.classList.toggle('is-visible', Boolean(text));
};

const getRequestErrorMessage = (error, fallback) => {
  const message = safeText(error?.message);
  if (message && message !== 'Failed to fetch') {
    return message;
  }

  return (
    fallback ||
    'Could not reach the sign-in service. Check that the API base URL points to a live backend.'
  );
};

const getFieldGroup = (input) => input?.closest('.field-group') || null;

const setFieldError = (input, message) => {
  const group = getFieldGroup(input);
  const errorEl = document.getElementById(`${input.id}-error`);
  if (group) group.classList.add('has-error');
  input.setAttribute('aria-invalid', 'true');
  if (errorEl) errorEl.textContent = message;
};

const clearFieldError = (input) => {
  const group = getFieldGroup(input);
  const errorEl = document.getElementById(`${input.id}-error`);
  if (group) group.classList.remove('has-error');
  input.removeAttribute('aria-invalid');
  if (errorEl) errorEl.textContent = '';
};

const clearFormErrors = (form) => {
  for (const input of form.querySelectorAll('input')) {
    clearFieldError(input);
  }
};

const setBusy = (button, busy, idleLabel, busyLabel) => {
  button.disabled = busy;
  button.textContent = busy ? busyLabel : idleLabel;
};

const finishAuth = (payload) => {
  if (window.opener && !window.opener.closed && targetOrigin) {
    window.opener.postMessage(
      {
        type: 'LOGIN_SUCCESS',
        user: payload?.user || null,
      },
      targetOrigin
    );
    window.close();
    return;
  }

  window.location.href = redirectUrl;
};

const parseJson = async (res) => {
  const text = await res.text();
  if (!text) return {};

  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
};

const showVerificationActions = (visible) => {
  verificationActions.classList.toggle('is-visible', visible);
  verificationActions.hidden = !visible;
};

const updatePasswordStrength = () => {
  const password = registerPasswordInput.value;
  let score = 0;

  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;

  const clampedScore = Math.min(score, 5);
  const percentage = clampedScore === 0 ? 0 : 20 + clampedScore * 16;
  const copy =
    clampedScore <= 1
      ? 'Very weak. Add length, uppercase, lowercase, and numbers.'
      : clampedScore === 2
        ? 'Weak. This still needs more variety.'
        : clampedScore === 3
          ? 'Decent. Add more length or symbols to strengthen it.'
          : clampedScore === 4
            ? 'Strong. This meets the current sign-in requirements well.'
            : 'Very strong. Good coverage and length.';

  registerPasswordStrength.dataset.score = String(clampedScore);
  registerPasswordStrengthFill.style.width = `${percentage}%`;
  registerPasswordStrengthCopy.textContent = copy;
};

const togglePasswordVisibility = (button) => {
  const input = document.getElementById(button.getAttribute('data-target'));
  if (!input) return;

  const nextType = input.type === 'password' ? 'text' : 'password';
  input.type = nextType;
  const isVisible = nextType === 'text';
  button.textContent = isVisible ? 'Hide' : 'Show';
  button.setAttribute('aria-pressed', isVisible ? 'true' : 'false');
};

const setCapsWarning = (input, visible) => {
  const warningEl = document.getElementById(`${input.id}-caps`);
  if (!warningEl) return;
  warningEl.classList.toggle('is-visible', Boolean(visible));
};

const handleCapsLockState = (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || target.type !== 'password') return;
  setCapsWarning(target, event.getModifierState('CapsLock'));
};

const validateIdentifier = (input) => {
  const value = safeText(input.value);
  clearFieldError(input);

  if (!value) {
    setFieldError(input, 'Enter your email address or username.');
    return false;
  }

  if (value.includes('@') && !EMAIL_PATTERN.test(value)) {
    setFieldError(input, 'Enter a valid email address.');
    return false;
  }

  if (!value.includes('@') && !USERNAME_PATTERN.test(value)) {
    setFieldError(
      input,
      'Enter a valid username. Use letters, numbers, dots, hyphens, or underscores.'
    );
    return false;
  }

  return true;
};

const validateLoginForm = () => {
  let valid = true;
  clearFormErrors(loginForm);

  if (!validateIdentifier(loginIdentifierInput)) valid = false;

  if (!loginPasswordInput.value) {
    setFieldError(loginPasswordInput, 'Enter your password.');
    valid = false;
  }

  if (!awaitingMfa) {
    return valid;
  }

  if (activeMfaMethod === 'totp') {
    if (!safeText(loginMfaCode.value)) {
      setFieldError(loginMfaCode, 'Enter the authenticator code from your app.');
      valid = false;
    }
  } else if (!safeText(loginBackupCode.value)) {
    setFieldError(loginBackupCode, 'Enter one of your backup codes.');
    valid = false;
  }

  return valid;
};

const validateRegisterForm = () => {
  let valid = true;
  clearFormErrors(registerForm);

  const username = safeText(registerUsernameInput.value);
  const displayName = safeText(registerDisplayNameInput.value);
  const email = safeText(registerEmailInput.value);
  const password = registerPasswordInput.value;
  const confirmPassword = registerConfirmPasswordInput.value;

  if (!username) {
    setFieldError(registerUsernameInput, 'Choose a username.');
    valid = false;
  } else if (!USERNAME_PATTERN.test(username)) {
    setFieldError(
      registerUsernameInput,
      'Usernames must start and end with letters or numbers and may include dots, hyphens, or underscores.'
    );
    valid = false;
  }

  if (displayName.length > 60) {
    setFieldError(registerDisplayNameInput, 'Display name must be 60 characters or fewer.');
    valid = false;
  }

  if (!email) {
    setFieldError(registerEmailInput, 'Enter your email address.');
    valid = false;
  } else if (!EMAIL_PATTERN.test(email)) {
    setFieldError(registerEmailInput, 'Enter a valid email address.');
    valid = false;
  }

  if (!password) {
    setFieldError(registerPasswordInput, 'Create a password.');
    valid = false;
  } else if (
    password.length < 8 ||
    !/[A-Z]/.test(password) ||
    !/[a-z]/.test(password) ||
    !/\d/.test(password)
  ) {
    setFieldError(
      registerPasswordInput,
      'Use at least 8 characters with uppercase, lowercase, and a number.'
    );
    valid = false;
  }

  if (!confirmPassword) {
    setFieldError(registerConfirmPasswordInput, 'Repeat your password.');
    valid = false;
  } else if (password !== confirmPassword) {
    setFieldError(registerConfirmPasswordInput, 'Passwords do not match.');
    valid = false;
  }

  return valid;
};

const cycleTabs = (tabs, currentIndex, direction) => {
  const offset = direction === 'next' ? 1 : -1;
  return (currentIndex + offset + tabs.length) % tabs.length;
};

const switchTabs = (target, { focus = true } = {}) => {
  const showLogin = target === 'login';

  loginToggle.setAttribute('aria-selected', showLogin ? 'true' : 'false');
  loginToggle.tabIndex = showLogin ? 0 : -1;
  registerToggle.setAttribute('aria-selected', showLogin ? 'false' : 'true');
  registerToggle.tabIndex = showLogin ? -1 : 0;
  loginPanel.hidden = !showLogin;
  registerPanel.hidden = showLogin;
  clearFormErrors(loginForm);
  clearFormErrors(registerForm);
  resetLoginChallenge();

  if (!showLogin) {
    showVerificationActions(false);
  }

  if (focus) {
    (showLogin ? loginIdentifierInput : registerUsernameInput).focus();
  }

  setStatus('', 'info');
};

const handleAuthTabKeydown = (event) => {
  const tabs = [loginToggle, registerToggle];
  const currentIndex = tabs.indexOf(event.currentTarget);
  if (currentIndex === -1) return;

  if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
    event.preventDefault();
    const nextIndex = cycleTabs(tabs, currentIndex, event.key === 'ArrowRight' ? 'next' : 'prev');
    tabs[nextIndex].focus();
    switchTabs(nextIndex === 0 ? 'login' : 'register', { focus: false });
  }

  if (event.key === 'Home') {
    event.preventDefault();
    loginToggle.focus();
    switchTabs('login', { focus: false });
  }

  if (event.key === 'End') {
    event.preventDefault();
    registerToggle.focus();
    switchTabs('register', { focus: false });
  }
};

const setMfaMethod = (method, { focus = false } = {}) => {
  activeMfaMethod = method === 'backup' ? 'backup' : 'totp';
  const showingTotp = activeMfaMethod === 'totp';

  mfaMethodTotp.classList.toggle('is-active', showingTotp);
  mfaMethodTotp.setAttribute('aria-selected', showingTotp ? 'true' : 'false');
  mfaMethodTotp.tabIndex = showingTotp ? 0 : -1;
  mfaMethodBackup.classList.toggle('is-active', !showingTotp);
  mfaMethodBackup.setAttribute('aria-selected', showingTotp ? 'false' : 'true');
  mfaMethodBackup.tabIndex = showingTotp ? -1 : 0;
  mfaPanelTotp.hidden = !showingTotp;
  mfaPanelBackup.hidden = showingTotp;
  clearFieldError(loginMfaCode);
  clearFieldError(loginBackupCode);

  if (focus) {
    (showingTotp ? loginMfaCode : loginBackupCode).focus();
  }
};

const handleMfaTabKeydown = (event) => {
  const tabs = [mfaMethodTotp, mfaMethodBackup];
  const currentIndex = tabs.indexOf(event.currentTarget);
  if (currentIndex === -1) return;

  if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
    event.preventDefault();
    const nextIndex = cycleTabs(tabs, currentIndex, event.key === 'ArrowRight' ? 'next' : 'prev');
    tabs[nextIndex].focus();
    setMfaMethod(nextIndex === 0 ? 'totp' : 'backup');
  }

  if (event.key === 'Home') {
    event.preventDefault();
    mfaMethodTotp.focus();
    setMfaMethod('totp');
  }

  if (event.key === 'End') {
    event.preventDefault();
    mfaMethodBackup.focus();
    setMfaMethod('backup');
  }
};

const resetLoginChallenge = ({ clearStatus = false } = {}) => {
  awaitingMfa = false;
  loginPrimaryFields.hidden = false;
  loginMfaStep.classList.remove('is-visible');
  loginMfaCode.value = '';
  loginBackupCode.value = '';
  loginMfaHelper.textContent = 'Keep this window open until the sign-in finishes.';
  clearFieldError(loginMfaCode);
  clearFieldError(loginBackupCode);
  setMfaMethod('totp');
  loginBtn.textContent = 'Sign in';
  if (clearStatus) {
    setStatus('', 'info');
  }
};

const showMfaStep = (message) => {
  awaitingMfa = true;
  loginPrimaryFields.hidden = true;
  loginMfaStep.classList.add('is-visible');
  loginMfaCopy.textContent =
    safeText(message) || 'Your password was accepted. Finish sign-in with your authenticator app or a backup code.';
  loginMfaHelper.textContent = 'Primary credentials accepted. Finish sign-in with your second factor.';
  loginBtn.textContent = 'Verify and sign in';
  showVerificationActions(false);
  setMfaMethod('totp', { focus: true });
};

const clearCooldown = () => {
  if (loginCooldownTimer) {
    window.clearInterval(loginCooldownTimer);
    loginCooldownTimer = 0;
  }
  loginCooldownUntil = 0;
  loginBtn.disabled = false;
  loginBtn.textContent = awaitingMfa ? 'Verify and sign in' : 'Sign in';
};

const startLoginCooldown = (retryAfterSec) => {
  const seconds = Math.max(1, Number(retryAfterSec || 0));
  clearCooldown();
  loginCooldownUntil = Date.now() + seconds * 1000;

  const updateCountdown = () => {
    const remaining = Math.max(0, Math.ceil((loginCooldownUntil - Date.now()) / 1000));
    loginBtn.disabled = remaining > 0;

    if (remaining <= 0) {
      clearCooldown();
      setStatus('You can try signing in again now.', 'info');
      return;
    }

    loginBtn.textContent = `Try again in ${remaining}s`;
    setStatus(`Too many failed attempts. Try again in ${remaining} seconds.`, 'warn');
  };

  updateCountdown();
  loginCooldownTimer = window.setInterval(updateCountdown, 1000);
};

const handleResendVerification = async () => {
  const identifier = pendingVerificationIdentifier || safeText(loginIdentifierInput.value);
  if (!identifier) {
    setStatus('Enter your email or username first so we know where to resend the verification link.', 'warn');
    loginIdentifierInput.focus();
    return;
  }

  resendVerificationBtn.disabled = true;
  setStatus('Sending a fresh verification link...', 'info');

  try {
    const res = await fetch(`${AUTH_API_BASE}/resend-verification-public`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier }),
    });
    const data = await parseJson(res);
    setStatus(
      data.message || 'If that account is still unverified, a new verification link will arrive shortly.',
      'success'
    );
  } catch (error) {
    setStatus(
      getRequestErrorMessage(
        error,
        'Could not reach the verification service. Check that the API base URL points to a live backend.'
      ),
      'error'
    );
  } finally {
    resendVerificationBtn.disabled = false;
  }
};

const requestAuth = async (endpoint, body, submitButton, labels) => {
  setBusy(submitButton, true, labels.idle, labels.busy);
  setStatus(endpoint === '/login' ? 'Checking your credentials...' : 'Creating your account...', 'info');

  try {
    const res = await fetch(`${AUTH_API_BASE}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(body),
    });
    const data = await parseJson(res);

    if (!res.ok) {
      if (endpoint === '/login' && data.retryAfterSec) {
        startLoginCooldown(data.retryAfterSec);
        return;
      }

      if (endpoint === '/login' && data.mfaRequired) {
        showMfaStep(data.message);
        setStatus(data.message || 'Enter your authenticator code to continue.', 'info');
        return;
      }

      if (data.requiresVerification) {
        pendingVerificationIdentifier = body.identifier || body.email || body.username || '';
        if (endpoint === '/register') {
          loginIdentifierInput.value = body.email || body.username || '';
          switchTabs('login');
        }
        resetLoginChallenge();
        showVerificationActions(true);
        setStatus(
          data.message || 'Verify your email before signing in.',
          data.verificationEmail?.sent === false ? 'warn' : 'success'
        );
        return;
      }

      throw new Error(data.message || 'Authentication failed.');
    }

    const isAuthenticated =
      typeof data.authenticated === 'boolean'
        ? data.authenticated
        : Boolean(data.accessToken || data.token);

    if (!isAuthenticated) {
      pendingVerificationIdentifier = body.identifier || body.email || body.username || '';
      if (endpoint === '/register') {
        loginIdentifierInput.value = body.email || body.username || '';
        switchTabs('login');
      }
      resetLoginChallenge();
      showVerificationActions(Boolean(data.requiresVerification || endpoint === '/register'));
      setStatus(
        data.message || 'Check your inbox to verify your email before signing in.',
        data.verificationEmail?.sent === false ? 'warn' : 'success'
      );
      return;
    }

    pendingVerificationIdentifier = '';
    clearCooldown();
    resetLoginChallenge();
    showVerificationActions(false);
    setStatus('Success. Continuing...', 'success');
    finishAuth(data);
  } catch (error) {
    setStatus(getRequestErrorMessage(error, 'Authentication failed.'), 'error');
  } finally {
    if (!loginCooldownTimer) {
      setBusy(submitButton, false, labels.idle, labels.busy);
    }
  }
};

loginToggle.addEventListener('click', () => switchTabs('login'));
registerToggle.addEventListener('click', () => switchTabs('register'));
loginToggle.addEventListener('keydown', handleAuthTabKeydown);
registerToggle.addEventListener('keydown', handleAuthTabKeydown);
mfaMethodTotp.addEventListener('click', () => setMfaMethod('totp', { focus: true }));
mfaMethodBackup.addEventListener('click', () => setMfaMethod('backup', { focus: true }));
mfaMethodTotp.addEventListener('keydown', handleMfaTabKeydown);
mfaMethodBackup.addEventListener('keydown', handleMfaTabKeydown);

loginMfaBackBtn.addEventListener('click', () => {
  resetLoginChallenge({ clearStatus: true });
  loginPasswordInput.focus();
});

const resetUrl = new URL('reset-password.html', window.location.href);
if (params.get('origin')) resetUrl.searchParams.set('origin', params.get('origin'));
if (params.get('redirect')) resetUrl.searchParams.set('redirect', params.get('redirect'));
if (params.get('apiBaseUrl')) resetUrl.searchParams.set('apiBaseUrl', params.get('apiBaseUrl'));
forgotPasswordLink.href = resetUrl.toString();
verificationResetBtn.addEventListener('click', () => {
  window.location.href = resetUrl.toString();
});

openFullPageLink.href = window.location.href;
openFullPageLink.target = '_blank';
openFullPageLink.rel = 'noopener noreferrer';

for (const toggle of document.querySelectorAll('[data-password-toggle]')) {
  toggle.addEventListener('click', () => togglePasswordVisibility(toggle));
}

for (const passwordInput of [loginPasswordInput, registerPasswordInput, registerConfirmPasswordInput]) {
  passwordInput.addEventListener('keydown', handleCapsLockState);
  passwordInput.addEventListener('keyup', handleCapsLockState);
  passwordInput.addEventListener('blur', () => setCapsWarning(passwordInput, false));
}

registerPasswordInput.addEventListener('input', updatePasswordStrength);

for (const form of [loginForm, registerForm]) {
  form.addEventListener('input', (event) => {
    if (event.target instanceof HTMLInputElement) {
      clearFieldError(event.target);
    }
  });
}

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  if (loginCooldownUntil > Date.now()) {
    setStatus(
      `Too many failed attempts. Try again in ${Math.ceil((loginCooldownUntil - Date.now()) / 1000)} seconds.`,
      'warn'
    );
    return;
  }

  if (!validateLoginForm()) {
    setStatus('Check the highlighted fields and try again.', 'error');
    return;
  }

  await requestAuth(
    '/login',
    {
      identifier: safeText(loginIdentifierInput.value),
      password: loginPasswordInput.value,
      mfaCode: activeMfaMethod === 'totp' ? safeText(loginMfaCode.value) : '',
      backupCode: activeMfaMethod === 'backup' ? safeText(loginBackupCode.value) : '',
    },
    loginBtn,
    {
      idle: awaitingMfa ? 'Verify and sign in' : 'Sign in',
      busy: awaitingMfa ? 'Verifying...' : 'Signing in...',
    }
  );
});

registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  if (!validateRegisterForm()) {
    setStatus('Check the highlighted fields and try again.', 'error');
    return;
  }

  await requestAuth(
    '/register',
    {
      username: safeText(registerUsernameInput.value),
      displayName: safeText(registerDisplayNameInput.value),
      email: safeText(registerEmailInput.value),
      password: registerPasswordInput.value,
    },
    registerBtn,
    { idle: 'Create account', busy: 'Creating account...' }
  );
});

resendVerificationBtn.addEventListener('click', handleResendVerification);
updatePasswordStrength();
showVerificationActions(false);
resetLoginChallenge({ clearStatus: true });
