const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1']);
const REFRESH_INTERVAL_MS = 5 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 15_000;
const ACTIVE_TAB_STORAGE_KEY = 'dashboard.activeTab';

const dom = {
  loadingScreen: document.getElementById('loading-screen'),
  loadingMessage: document.getElementById('loading-message'),
  appContent: document.getElementById('app-content'),
  toastRegion: document.getElementById('toast-region'),

  status: document.getElementById('status'),
  connectionStatus: document.getElementById('connection-status'),
  syncStatus: document.getElementById('sync-status'),

  logoutBtn: document.getElementById('logout-btn'),
  refreshDataBtn: document.getElementById('refresh-data-btn'),
  headerExportJsonBtn: document.getElementById('header-export-json-btn'),

  tabButtons: Array.from(document.querySelectorAll('.tab-btn')),
  tabContents: Array.from(document.querySelectorAll('.tab-content')),

  summaryId: document.getElementById('summary-id'),
  summaryDisplayName: document.getElementById('summary-display-name'),
  summaryLastLogin: document.getElementById('summary-last-login'),
  summaryVerified: document.getElementById('summary-verified'),
  summarySessions: document.getElementById('summary-sessions'),
  summaryCompletion: document.getElementById('summary-completion'),

  insightLast7: document.getElementById('insight-last7'),
  insightLast30: document.getElementById('insight-last30'),
  insightIps: document.getElementById('insight-ips'),
  insightVerified: document.getElementById('insight-verified'),

  profileForm: document.getElementById('profile-form'),
  profileSaveBtn: document.getElementById('profile-save-btn'),
  profileDisplayName: document.getElementById('profile-display-name'),
  profileEmail: document.getElementById('profile-email'),
  profileLocation: document.getElementById('profile-location'),
  profileWebsite: document.getElementById('profile-website'),
  profileTimezone: document.getElementById('profile-timezone'),
  profileLanguage: document.getElementById('profile-language'),
  profileBio: document.getElementById('profile-bio'),
  profileId: document.getElementById('profile-id'),
  profileCreated: document.getElementById('profile-created'),
  profileProgressBar: document.getElementById('profile-progress-bar'),
  profileProgressLabel: document.getElementById('profile-progress-label'),

  linkedForm: document.getElementById('linked-form'),
  linkedSaveBtn: document.getElementById('linked-save-btn'),
  linkedGoogle: document.getElementById('linked-google'),
  linkedFacebook: document.getElementById('linked-facebook'),
  linkedGithub: document.getElementById('linked-github'),
  linkedTwitter: document.getElementById('linked-twitter'),
  linkedLinkedin: document.getElementById('linked-linkedin'),
  linkedDiscord: document.getElementById('linked-discord'),
  linkedApple: document.getElementById('linked-apple'),
  linkedMicrosoft: document.getElementById('linked-microsoft'),

  passwordForm: document.getElementById('password-form'),
  passwordSaveBtn: document.getElementById('password-save-btn'),
  currentPassword: document.getElementById('current-password'),
  newPassword: document.getElementById('new-password'),
  confirmPassword: document.getElementById('confirm-password'),
  passwordStrengthFill: document.getElementById('password-strength-fill'),
  passwordStrengthText: document.getElementById('password-strength-text'),

  securityForm: document.getElementById('security-form'),
  securitySaveBtn: document.getElementById('security-save-btn'),
  loginAlertsToggle: document.getElementById('login-alerts-toggle'),
  sessionLimitNote: document.getElementById('session-limit-note'),

  privacyForm: document.getElementById('privacy-form'),
  privacySaveBtn: document.getElementById('privacy-save-btn'),
  privacyPublic: document.getElementById('privacy-public'),
  privacySearchable: document.getElementById('privacy-searchable'),

  notificationForm: document.getElementById('notification-form'),
  notificationSaveBtn: document.getElementById('notification-save-btn'),
  notifyEmail: document.getElementById('notify-email'),
  notifySms: document.getElementById('notify-sms'),
  notifyPush: document.getElementById('notify-push'),
  notifyWeeklyDigest: document.getElementById('notify-weekly-digest'),
  notifySecurity: document.getElementById('notify-security'),

  appearanceForm: document.getElementById('appearance-form'),
  appearanceSaveBtn: document.getElementById('appearance-save-btn'),
  appearanceResetBtn: document.getElementById('appearance-reset-btn'),
  appearanceTheme: document.getElementById('appearance-theme'),
  appearanceDensity: document.getElementById('appearance-density'),
  appearanceCompactMode: document.getElementById('appearance-compact-mode'),
  appearanceReducedMotion: document.getElementById('appearance-reduced-motion'),
  appearanceHighContrast: document.getElementById('appearance-high-contrast'),
  dashboardTipsToggle: document.getElementById('dashboard-tips-toggle'),

  sessionsList: document.getElementById('sessions-list'),
  sessionsRefreshBtn: document.getElementById('sessions-refresh-btn'),
  sessionsRevokeOthersBtn: document.getElementById('sessions-revoke-others-btn'),
  sessionsRevokeAllBtn: document.getElementById('sessions-revoke-all-btn'),

  activityList: document.getElementById('activity-list'),
  activityFilter: document.getElementById('activity-filter'),
  activityRefreshBtn: document.getElementById('activity-refresh-btn'),
  activityExportBtn: document.getElementById('activity-export-btn'),
  activityBars: document.getElementById('activity-bars'),

  deleteForm: document.getElementById('delete-form'),
  deleteAccountBtn: document.getElementById('delete-account-btn'),
  deletePassword: document.getElementById('delete-password'),
  deleteConfirmText: document.getElementById('delete-confirm-text'),

  serviceFilter: document.getElementById('service-filter'),
  serviceCards: Array.from(document.querySelectorAll('#service-list .card')),

  cookiePopup: document.getElementById('cookie-popup'),
  cookieAcceptBtn: document.getElementById('cookie-accept'),
};

const trimTrailingSlash = (value) => String(value || '').replace(/\/+$/, '');
const safeText = (value) => String(value || '').trim();

const getDefaultApiBaseUrl = () => {
  if (LOCAL_HOSTS.has(window.location.hostname)) {
    return 'http://localhost:5000';
  }

  if (
    window.location.hostname === 'dashboard.continental-hub.com' ||
    window.location.hostname === 'login.continental-hub.com'
  ) {
    return 'https://grimoire.continental-hub.com';
  }

  return window.location.origin;
};

const API_BASE_URL = trimTrailingSlash(
  window.__API_BASE_URL__ || getDefaultApiBaseUrl()
);
const AUTH_API_BASE = `${API_BASE_URL}/api/auth`;

const getDefaultLoginPopupUrl = () => {
  if (LOCAL_HOSTS.has(window.location.hostname)) {
    return new URL('../login popup/popup.html', window.location.href).toString();
  }

  return 'https://login.continental-hub.com/popup.html';
};

const DEFAULT_LOGIN_POPUP_URL = getDefaultLoginPopupUrl();
const LOGIN_POPUP_URL = window.__LOGIN_POPUP_URL__ || DEFAULT_LOGIN_POPUP_URL;

const loginPopupOrigin = (() => {
  try {
    return new URL(LOGIN_POPUP_URL, window.location.href).origin;
  } catch {
    return null;
  }
})();

const state = {
  user: null,
  activity: [],
  activitySummary: {
    last7Days: 0,
    last30Days: 0,
    uniqueIps: 0,
    recentDays: [],
  },
  sessions: [],
  sessionLimit: null,
  accessToken: '',
  loginPopupWindow: null,
  appVisible: false,
  refreshTimer: null,
  lastSyncAt: null,
};

const trackedForms = [
  dom.profileForm,
  dom.linkedForm,
  dom.securityForm,
  dom.privacyForm,
  dom.notificationForm,
  dom.appearanceForm,
];

const formatDate = (value) => {
  const date = new Date(value || '');
  if (Number.isNaN(date.getTime())) return 'Unavailable';
  return date.toLocaleString();
};

const isDashboardTipsEnabled = () => localStorage.getItem('dashboardTipsEnabled') !== 'false';

const setButtonBusy = (button, busy, busyLabel) => {
  if (!button) return;

  if (busy) {
    if (!button.dataset.defaultLabel) {
      button.dataset.defaultLabel = button.textContent;
    }
    button.disabled = true;
    if (busyLabel) button.textContent = busyLabel;
    return;
  }

  button.disabled = false;
  if (button.dataset.defaultLabel) {
    button.textContent = button.dataset.defaultLabel;
  }
};

const markFormDirty = (form) => {
  if (!form) return;
  form.dataset.dirty = 'true';
};

const markFormClean = (form) => {
  if (!form) return;
  form.dataset.dirty = 'false';
};

const hasUnsavedChanges = () => trackedForms.some((form) => form?.dataset.dirty === 'true');

const setupUnsavedChangeTracking = () => {
  for (const form of trackedForms) {
    if (!form) continue;

    form.dataset.dirty = 'false';

    form.addEventListener('input', () => {
      markFormDirty(form);
    });
    form.addEventListener('change', () => {
      markFormDirty(form);
    });
  }
};

const showToast = (message, type = 'success', timeoutMs = 3200) => {
  if (!dom.toastRegion) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  dom.toastRegion.appendChild(toast);

  window.setTimeout(() => {
    toast.remove();
  }, timeoutMs);
};

const setStatus = (text, options = {}) => {
  const { clickable = false, onClick = null } = options;
  if (!dom.status) return;

  dom.status.textContent = text;
  dom.status.style.cursor = clickable ? 'pointer' : 'default';
  dom.status.onclick = clickable ? onClick : null;
};

const setConnectionStatus = () => {
  const online = navigator.onLine;
  if (dom.connectionStatus) {
    dom.connectionStatus.textContent = online ? 'Online' : 'Offline';
    dom.connectionStatus.classList.toggle('offline', !online);
  }
};

const setSyncStatus = (date = null) => {
  if (!dom.syncStatus) return;
  if (!date) {
    dom.syncStatus.textContent = 'Not synced yet';
    return;
  }
  dom.syncStatus.textContent = `Synced ${formatDate(date)}`;
};

const clearStoredAuth = () => {
  state.accessToken = '';
};

const storeSession = (data = {}) => {
  const token = data?.accessToken || data?.token;
  state.accessToken = safeText(token);
};

const parseResponseBody = async (res) => {
  const text = await res.text();
  if (!text) return {};

  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
};

const fetchWithTimeout = async (url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) => {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
    });
  } finally {
    window.clearTimeout(timeoutId);
  }
};

const openLoginPopup = () => {
  const width = 520;
  const height = 700;
  const left = window.screenX + (window.outerWidth - width) / 2;
  const top = window.screenY + (window.outerHeight - height) / 2;

  const popupUrl = new URL(LOGIN_POPUP_URL, window.location.href);
  popupUrl.searchParams.set('origin', window.location.origin);
  popupUrl.searchParams.set('redirect', window.location.href);
  popupUrl.searchParams.set('apiBaseUrl', API_BASE_URL);

  if (state.loginPopupWindow && !state.loginPopupWindow.closed) {
    state.loginPopupWindow.focus();
    return state.loginPopupWindow;
  }

  state.loginPopupWindow = window.open(
    popupUrl.toString(),
    'LoginPopup',
    `width=${width},height=${height},top=${Math.max(top, 0)},left=${Math.max(left, 0)}`
  );

  return state.loginPopupWindow;
};

const closeLoginPopup = () => {
  if (state.loginPopupWindow && !state.loginPopupWindow.closed) {
    state.loginPopupWindow.close();
  }
};

const isTrustedLoginOrigin = (origin) => {
  if (!origin) return false;
  if (origin === window.location.origin) return true;
  if (loginPopupOrigin && origin === loginPopupOrigin) return true;

  try {
    const parsed = new URL(origin);
    return LOCAL_HOSTS.has(window.location.hostname) && LOCAL_HOSTS.has(parsed.hostname);
  } catch {
    return false;
  }
};

const clearDashboardUi = () => {
  state.user = null;
  state.activity = [];
  state.sessions = [];

  if (dom.summaryId) dom.summaryId.textContent = '-';
  if (dom.summaryDisplayName) dom.summaryDisplayName.textContent = '-';
  if (dom.summaryLastLogin) dom.summaryLastLogin.textContent = '-';
  if (dom.summaryVerified) dom.summaryVerified.textContent = 'Pending';
  if (dom.summarySessions) dom.summarySessions.textContent = '0';
  if (dom.summaryCompletion) dom.summaryCompletion.textContent = '0%';

  if (dom.profileProgressBar) dom.profileProgressBar.style.width = '0%';
  if (dom.profileProgressLabel) dom.profileProgressLabel.textContent = '0%';

  if (dom.profileForm) dom.profileForm.reset();
  if (dom.linkedForm) dom.linkedForm.reset();
  if (dom.passwordForm) dom.passwordForm.reset();
  if (dom.securityForm) dom.securityForm.reset();
  if (dom.privacyForm) dom.privacyForm.reset();
  if (dom.notificationForm) dom.notificationForm.reset();
  if (dom.appearanceForm) dom.appearanceForm.reset();
  if (dom.deleteForm) dom.deleteForm.reset();
  for (const form of trackedForms) {
    markFormClean(form);
  }

  if (dom.profileId) dom.profileId.value = '';
  if (dom.profileCreated) dom.profileCreated.value = '';

  if (dom.activityFilter) dom.activityFilter.value = '';
  if (dom.activityList) dom.activityList.innerHTML = '<li>No recent login activity found.</li>';
  if (dom.sessionsList) dom.sessionsList.innerHTML = '<li>No active sessions found.</li>';
  if (dom.activityBars) dom.activityBars.innerHTML = '';

  if (dom.insightLast7) dom.insightLast7.textContent = '0';
  if (dom.insightLast30) dom.insightLast30.textContent = '0';
  if (dom.insightIps) dom.insightIps.textContent = '0';
  if (dom.insightVerified) dom.insightVerified.textContent = 'Pending';

  applyAppearance({
    theme: 'system',
    compactMode: false,
    reducedMotion: false,
    highContrast: false,
    dashboardDensity: 'comfortable',
  });
};

const setLoggedOutUI = (openPopup = true) => {
  clearStoredAuth();
  clearDashboardUi();

  setStatus('Not logged in - click to sign in', {
    clickable: true,
    onClick: () => openLoginPopup(),
  });

  if (dom.logoutBtn) {
    dom.logoutBtn.style.display = 'none';
  }

  if (!state.appVisible && dom.loadingMessage) {
    dom.loadingMessage.textContent = 'Please sign in to continue.';
  }

  if (!openPopup) return;

  const popup = openLoginPopup();
  if (popup) return;

  if (dom.loadingMessage) {
    dom.loadingMessage.textContent = 'Login popup blocked. Click here to open login.';
  }

  if (dom.loadingScreen) {
    dom.loadingScreen.style.cursor = 'pointer';
    dom.loadingScreen.onclick = () => {
      const retry = openLoginPopup();
      if (!retry) return;
      dom.loadingScreen.style.cursor = 'default';
      dom.loadingScreen.onclick = null;
      if (dom.loadingMessage) {
        dom.loadingMessage.textContent = 'Waiting for login...';
      }
    };
  }
};

const extractParamsFromUrl = () => {
  const params = new URLSearchParams(window.location.search);
  const token = safeText(params.get('token'));
  const hadLegacyAuthParams =
    params.has('token') || params.has('userId') || params.has('continentalId');

  if (token) {
    storeSession({ token });
  }

  if (hadLegacyAuthParams) {
    params.delete('token');
    params.delete('userId');
    params.delete('continentalId');
    const nextQuery = params.toString();
    const nextUrl = `${window.location.pathname}${nextQuery ? `?${nextQuery}` : ''}${window.location.hash}`;
    history.replaceState({}, '', nextUrl);
  }

  return Boolean(token);
};

const refreshSession = async () => {
  try {
    const res = await fetchWithTimeout(`${AUTH_API_BASE}/refresh_token`, {
      method: 'POST',
      credentials: 'include',
    });

    const data = await parseResponseBody(res);
    if (!res.ok || !(data.accessToken || data.token)) {
      return null;
    }

    storeSession(data);
    return data;
  } catch {
    return null;
  }
};

const toApiError = (err) => {
  if (err?.name === 'AbortError') {
    return new Error('Request timed out. Please try again.');
  }

  if (err instanceof TypeError) {
    return new Error('Network error. Check your connection and try again.');
  }

  return err instanceof Error ? err : new Error('Unexpected request error.');
};

const apiRequest = async (path, options = {}) => {
  const { method = 'GET', body = undefined, auth = true, retryOn401 = true } = options;

  const headers = {};
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  if (auth) {
    const token = state.accessToken;
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }

  let response;
  try {
    response = await fetchWithTimeout(`${AUTH_API_BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'include',
    });
  } catch (error) {
    throw toApiError(error);
  }

  if (response.status === 401 && auth && retryOn401) {
    const refreshed = await refreshSession();
    if (refreshed) {
      return apiRequest(path, { method, body, auth, retryOn401: false });
    }
  }

  const payload = await parseResponseBody(response);

  if (!response.ok) {
    throw new Error(payload.message || `Request failed (${response.status})`);
  }

  return payload;
};

const normalizeUserPayload = (payload) => {
  if (!payload) return null;
  return payload.user || payload;
};

const normalizeWebsiteInput = (value) => {
  const raw = safeText(value);
  if (!raw) return '';

  const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    const parsed = new URL(withProtocol);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed.toString();
  } catch {
    return null;
  }
};

const evaluatePasswordStrength = (password) => {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;

  const percentage = Math.min(100, score * 20);
  let label = 'Very weak';
  let color = '#ff8b7c';

  if (score >= 2) {
    label = 'Weak';
    color = '#ffbe71';
  }
  if (score >= 3) {
    label = 'Moderate';
    color = '#ffe97b';
  }
  if (score >= 4) {
    label = 'Strong';
    color = '#95ebb1';
  }
  if (score >= 5) {
    label = 'Very strong';
    color = '#73e4ab';
  }

  return { score, percentage, label, color };
};

const updatePasswordStrengthUi = () => {
  if (!dom.newPassword || !dom.passwordStrengthFill || !dom.passwordStrengthText) return;

  const value = dom.newPassword.value;
  const strength = evaluatePasswordStrength(value);

  dom.passwordStrengthFill.style.width = `${strength.percentage}%`;
  dom.passwordStrengthFill.style.background = `linear-gradient(120deg, ${strength.color}, #7db4ff)`;

  if (!value) {
    dom.passwordStrengthText.textContent = 'Use 8+ chars with uppercase, lowercase, and number.';
    return;
  }

  dom.passwordStrengthText.textContent = `Password strength: ${strength.label}`;
};

const applyAppearance = (appearance = {}) => {
  const theme = safeText(appearance.theme || 'system').toLowerCase() || 'system';
  const density = safeText(appearance.dashboardDensity || 'comfortable').toLowerCase() || 'comfortable';
  const compactMode = Boolean(appearance.compactMode);
  const reducedMotion = Boolean(appearance.reducedMotion);
  const highContrast = Boolean(appearance.highContrast);

  const resolvedTheme = theme === 'system'
    ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'night' : 'dawn')
    : theme;

  document.documentElement.dataset.theme = resolvedTheme;
  document.documentElement.dataset.density = compactMode ? 'compact' : density;
  document.documentElement.dataset.reducedMotion = reducedMotion ? 'true' : 'false';
  document.documentElement.dataset.highContrast = highContrast ? 'true' : 'false';
};

const renderInsights = () => {
  if (dom.insightLast7) dom.insightLast7.textContent = String(state.activitySummary.last7Days || 0);
  if (dom.insightLast30) dom.insightLast30.textContent = String(state.activitySummary.last30Days || 0);
  if (dom.insightIps) dom.insightIps.textContent = String(state.activitySummary.uniqueIps || 0);
  if (dom.insightVerified) dom.insightVerified.textContent = state.user?.isVerified ? 'Verified' : 'Pending';
};

const fillSummary = (user) => {
  if (dom.summaryId) dom.summaryId.textContent = user.continentalId || user.userId || '-';
  if (dom.summaryDisplayName) dom.summaryDisplayName.textContent = user.displayName || '-';
  if (dom.summaryLastLogin) dom.summaryLastLogin.textContent = formatDate(user.lastLoginAt);
  if (dom.summaryVerified) dom.summaryVerified.textContent = user.isVerified ? 'Verified' : 'Pending';
  if (dom.summarySessions) {
    dom.summarySessions.textContent = String(user.security?.activeSessions ?? state.sessions.length ?? 0);
  }

  const completion = Number(user.profile?.completion || 0);
  if (dom.summaryCompletion) dom.summaryCompletion.textContent = `${completion}%`;
  if (dom.profileProgressBar) dom.profileProgressBar.style.width = `${completion}%`;
  if (dom.profileProgressLabel) dom.profileProgressLabel.textContent = `${completion}%`;
};

const fillProfile = (user) => {
  if (dom.profileDisplayName) dom.profileDisplayName.value = user.displayName || '';
  if (dom.profileEmail) dom.profileEmail.value = user.email || '';
  if (dom.profileLocation) dom.profileLocation.value = user.profile?.location || '';
  if (dom.profileWebsite) dom.profileWebsite.value = user.profile?.website || '';
  if (dom.profileTimezone) dom.profileTimezone.value = user.profile?.timezone || '';
  if (dom.profileLanguage) dom.profileLanguage.value = user.profile?.language || '';
  if (dom.profileBio) dom.profileBio.value = user.profile?.bio || '';
  if (dom.profileId) dom.profileId.value = user.continentalId || user.userId || '';
  if (dom.profileCreated) dom.profileCreated.value = formatDate(user.createdAt);

  const completion = Number(user.profile?.completion || 0);
  if (dom.profileProgressBar) dom.profileProgressBar.style.width = `${completion}%`;
  if (dom.profileProgressLabel) dom.profileProgressLabel.textContent = `${completion}%`;
};

const fillLinkedAccounts = (user) => {
  const linked = user.linkedAccounts || {};
  if (dom.linkedGoogle) dom.linkedGoogle.value = linked.google || '';
  if (dom.linkedFacebook) dom.linkedFacebook.value = linked.facebook || '';
  if (dom.linkedGithub) dom.linkedGithub.value = linked.github || '';
  if (dom.linkedTwitter) dom.linkedTwitter.value = linked.twitter || '';
  if (dom.linkedLinkedin) dom.linkedLinkedin.value = linked.linkedin || '';
  if (dom.linkedDiscord) dom.linkedDiscord.value = linked.discord || '';
  if (dom.linkedApple) dom.linkedApple.value = linked.apple || '';
  if (dom.linkedMicrosoft) dom.linkedMicrosoft.value = linked.microsoft || '';
};

const fillPreferences = (user) => {
  const prefs = user.preferences || {};
  const notifications = prefs.notifications || {};
  const appearance = prefs.appearance || {};

  if (dom.privacyPublic) dom.privacyPublic.checked = Boolean(prefs.profilePublic);
  if (dom.privacySearchable) dom.privacySearchable.checked = Boolean(prefs.searchable);

  if (dom.notifyEmail) dom.notifyEmail.checked = Boolean(notifications.email);
  if (dom.notifySms) dom.notifySms.checked = Boolean(notifications.sms);
  if (dom.notifyPush) dom.notifyPush.checked = Boolean(notifications.push);
  if (dom.notifyWeeklyDigest) dom.notifyWeeklyDigest.checked = Boolean(notifications.weeklyDigest);
  if (dom.notifySecurity) dom.notifySecurity.checked = Boolean(notifications.security);

  if (dom.appearanceTheme) dom.appearanceTheme.value = appearance.theme || 'system';
  if (dom.appearanceDensity) dom.appearanceDensity.value = appearance.dashboardDensity || 'comfortable';
  if (dom.appearanceCompactMode) dom.appearanceCompactMode.checked = Boolean(appearance.compactMode);
  if (dom.appearanceReducedMotion) dom.appearanceReducedMotion.checked = Boolean(appearance.reducedMotion);
  if (dom.appearanceHighContrast) dom.appearanceHighContrast.checked = Boolean(appearance.highContrast);
  if (dom.dashboardTipsToggle) dom.dashboardTipsToggle.checked = isDashboardTipsEnabled();

  applyAppearance(appearance);
};

const fillSecurity = (user) => {
  if (dom.loginAlertsToggle) dom.loginAlertsToggle.checked = Boolean(user.security?.loginAlerts);
};

const formatActivityLine = (entry) => {
  const at = formatDate(entry.at);
  const ip = safeText(entry.ip) || 'Unknown IP';
  const ua = safeText(entry.userAgent) || 'Unknown browser/device';
  return `${at} - Login from ${ip} (${ua})`;
};

const renderActivityBars = () => {
  if (!dom.activityBars) return;

  dom.activityBars.innerHTML = '';

  const days = Array.isArray(state.activitySummary.recentDays) ? state.activitySummary.recentDays : [];
  if (!days.length) return;

  const max = Math.max(...days.map((item) => Number(item.count || 0)), 1);

  for (const item of days) {
    const bar = document.createElement('div');
    bar.className = 'mini-bar';

    const fill = document.createElement('div');
    fill.className = 'mini-bar-fill';
    fill.style.height = `${Math.max(8, Math.round((Number(item.count || 0) / max) * 42))}px`;
    fill.title = `${item.day}: ${item.count}`;

    const label = document.createElement('span');
    label.className = 'mini-bar-label';
    label.textContent = safeText(item.day).slice(5);

    bar.appendChild(fill);
    bar.appendChild(label);
    dom.activityBars.appendChild(bar);
  }
};

const renderActivity = () => {
  if (!dom.activityList) return;

  const query = safeText(dom.activityFilter?.value).toLowerCase();
  dom.activityList.innerHTML = '';

  const filtered = state.activity.filter((entry) => {
    if (!query) return true;
    return formatActivityLine(entry).toLowerCase().includes(query);
  });

  if (filtered.length === 0) {
    const li = document.createElement('li');
    li.textContent = query ? 'No activity items match this filter.' : 'No recent login activity found.';
    dom.activityList.appendChild(li);
    return;
  }

  for (const entry of filtered) {
    const li = document.createElement('li');
    li.textContent = formatActivityLine(entry);
    dom.activityList.appendChild(li);
  }
};

const renderSessions = () => {
  if (!dom.sessionsList) return;

  dom.sessionsList.innerHTML = '';

  if (!state.sessions.length) {
    const li = document.createElement('li');
    li.textContent = 'No active sessions found.';
    dom.sessionsList.appendChild(li);
    return;
  }

  for (const session of state.sessions) {
    const li = document.createElement('li');
    li.className = 'session-row';

    const head = document.createElement('div');
    head.className = 'session-head';

    const left = document.createElement('div');
    left.textContent = safeText(session.label) || 'Browser session';

    const right = document.createElement('div');
    right.className = 'session-actions';

    if (session.current) {
      const chip = document.createElement('span');
      chip.className = 'inline-chip';
      chip.textContent = 'Current';
      right.appendChild(chip);
    }

    const revokeBtn = document.createElement('button');
    revokeBtn.type = 'button';
    revokeBtn.className = 'secondary-btn';
    revokeBtn.textContent = session.current ? 'Revoke Current Session' : 'Revoke';
    revokeBtn.addEventListener('click', async () => {
      const shouldContinue = session.current
        ? window.confirm('Revoking current session may require re-login. Continue?')
        : window.confirm('Revoke this session?');
      if (!shouldContinue) return;

      setButtonBusy(revokeBtn, true, 'Revoking...');
      try {
        const data = await apiRequest(`/sessions/${encodeURIComponent(session.sid)}`, {
          method: 'DELETE',
          body: {},
        });

        showToast(data.message || 'Session revoked.', 'success');

        if (data.forceRelogin) {
          clearStoredAuth();
          if (state.refreshTimer) {
            clearInterval(state.refreshTimer);
            state.refreshTimer = null;
          }
          setLoggedOutUI(true);
          return;
        }

        await Promise.all([loadSessions(), loadCurrentUser()]);
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(revokeBtn, false);
      }
    });
    right.appendChild(revokeBtn);

    head.appendChild(left);
    head.appendChild(right);

    const meta = document.createElement('div');
    meta.className = 'session-meta';
    meta.textContent = `Last used: ${formatDate(session.lastUsedAt)} | Created: ${formatDate(session.createdAt)} | IP: ${safeText(session.ip) || 'Unknown'} | ${safeText(session.userAgent) || 'Unknown device'}`;

    li.appendChild(head);
    li.appendChild(meta);
    dom.sessionsList.appendChild(li);
  }
};

const syncUiWithUser = (user) => {
  if (!user) return;

  state.user = user;

  fillSummary(user);
  fillProfile(user);
  fillLinkedAccounts(user);
  fillPreferences(user);
  fillSecurity(user);
  renderInsights();

  const statusText = `Logged in as: ${user.email || user.displayName || user.userId}`;
  setStatus(statusText, { clickable: false });

  if (dom.logoutBtn) {
    dom.logoutBtn.style.display = 'inline-flex';
  }
};

const loadCurrentUser = async () => {
  const payload = await apiRequest('/me', { method: 'GET', auth: true });
  const user = normalizeUserPayload(payload);

  syncUiWithUser(user);
  return user;
};

const loadActivity = async () => {
  const data = await apiRequest('/activity', { method: 'GET', auth: true });
  state.activity = Array.isArray(data.recentLogins) ? data.recentLogins : [];

  state.activitySummary = {
    last7Days: Number(data.summary?.last7Days || 0),
    last30Days: Number(data.summary?.last30Days || 0),
    uniqueIps: Number(data.summary?.uniqueIps || 0),
    recentDays: Array.isArray(data.summary?.recentDays) ? data.summary.recentDays : [],
  };

  renderActivity();
  renderActivityBars();
  renderInsights();
};

const loadPreferences = async () => {
  const data = await apiRequest('/preferences', { method: 'GET', auth: true });
  if (!state.user) state.user = {};
  state.user.preferences = data.preferences || state.user.preferences || {};
  fillPreferences(state.user);
};

const loadLinkedAccounts = async () => {
  const data = await apiRequest('/linked', { method: 'GET', auth: true });
  if (!state.user) state.user = {};
  state.user.linkedAccounts = data.linkedAccounts || state.user.linkedAccounts || {};
  fillLinkedAccounts(state.user);
};

const loadSecurity = async () => {
  const data = await apiRequest('/security', { method: 'GET', auth: true });
  if (!state.user) state.user = {};
  state.user.security = data.security || state.user.security || {};
  state.sessionLimit = data.sessionLimit || state.sessionLimit;
  fillSecurity(state.user);

  if (dom.sessionLimitNote) {
    const limitText = state.sessionLimit ? `${state.sessionLimit}` : '--';
    dom.sessionLimitNote.textContent = `Session limit: ${limitText}`;
  }
};

const loadSessions = async () => {
  const data = await apiRequest('/sessions', { method: 'GET', auth: true });
  state.sessions = Array.isArray(data.sessions) ? data.sessions : [];
  state.sessionLimit = data.sessionLimit || state.sessionLimit;

  if (!state.user) state.user = {};
  if (!state.user.security) state.user.security = {};
  state.user.security.activeSessions = state.sessions.length;

  if (dom.summarySessions) {
    dom.summarySessions.textContent = String(state.sessions.length);
  }

  renderSessions();

  if (dom.sessionLimitNote) {
    const limitText = state.sessionLimit ? `${state.sessionLimit}` : '--';
    dom.sessionLimitNote.textContent = `Session limit: ${limitText}`;
  }
};

const loadDashboardData = async ({ silent = false } = {}) => {
  if (!silent && dom.loadingMessage) {
    dom.loadingMessage.textContent = 'Loading dashboard...';
  }

  const user = await loadCurrentUser();

  await Promise.all([
    loadActivity(),
    loadPreferences(),
    loadLinkedAccounts(),
    loadSecurity(),
    loadSessions(),
  ]);

  syncUiWithUser(user);
  for (const form of trackedForms) {
    markFormClean(form);
  }
  state.lastSyncAt = new Date();
  setSyncStatus(state.lastSyncAt);
};

const showApp = () => {
  if (state.appVisible) return;
  state.appVisible = true;

  if (!dom.loadingScreen || !dom.appContent) return;

  dom.loadingScreen.style.opacity = '0';
  setTimeout(() => {
    dom.loadingScreen.style.display = 'none';
    dom.appContent.style.display = 'grid';
    dom.appContent.offsetWidth;
    dom.appContent.classList.add('fade-in');

    if (dom.cookiePopup && dom.cookieAcceptBtn) {
      if (!localStorage.getItem('cookiesAccepted')) {
        dom.cookiePopup.classList.remove('hide');
      }

      dom.cookieAcceptBtn.onclick = () => {
        localStorage.setItem('cookiesAccepted', 'true');
        dom.cookiePopup.classList.add('hide');
      };
    }
  }, 650);
};

const initializeSession = async () => {
  extractParamsFromUrl();

  if (!state.accessToken) {
    const refreshed = await refreshSession();
    if (!refreshed) return false;
  }

  try {
    await loadDashboardData();
    return true;
  } catch {
    const refreshed = await refreshSession();
    if (!refreshed) return false;

    await loadDashboardData();
    return true;
  }
};

const doLogout = async () => {
  try {
    await apiRequest('/logout', { method: 'POST', auth: false });
  } catch {
    // local logout proceeds even if API logout fails
  }

  clearStoredAuth();
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }

  setLoggedOutUI(true);
  showToast('Logged out successfully.', 'success');
};

const exportActivityCsv = () => {
  if (!state.activity.length) {
    showToast('No activity to export.', 'warn');
    return;
  }

  const header = ['Timestamp', 'IP', 'User Agent'];
  const rows = state.activity.map((entry) => [
    formatDate(entry.at),
    safeText(entry.ip),
    safeText(entry.userAgent).replace(/\n/g, ' '),
  ]);

  const toCsvCell = (value) => `"${String(value || '').replaceAll('"', '""')}"`;
  const csvLines = [header, ...rows].map((line) => line.map(toCsvCell).join(','));
  const csv = csvLines.join('\n');

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = `continental-activity-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(url);
  showToast('Activity exported.', 'success');
};

const downloadJsonFile = (filename, data) => {
  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(url);
};

const exportAccountJson = async () => {
  const data = await apiRequest('/export', { method: 'GET', auth: true });
  const fileName = `continental-account-export-${new Date().toISOString().slice(0, 10)}.json`;
  downloadJsonFile(fileName, data);
  showToast('Account export downloaded.', 'success');
};

const handleProfileSave = async (event) => {
  event.preventDefault();

  const displayName = safeText(dom.profileDisplayName?.value);
  const email = safeText(dom.profileEmail?.value).toLowerCase();
  const website = normalizeWebsiteInput(dom.profileWebsite?.value);

  if (displayName.length < 2) {
    showToast('Display name must be at least 2 characters.', 'error');
    return;
  }

  if (website === null) {
    showToast('Website URL is invalid.', 'error');
    return;
  }

  setButtonBusy(dom.profileSaveBtn, true, 'Saving...');

  try {
    const profilePayload = {
      displayName,
      location: safeText(dom.profileLocation?.value),
      website,
      timezone: safeText(dom.profileTimezone?.value),
      language: safeText(dom.profileLanguage?.value),
      bio: safeText(dom.profileBio?.value),
    };

    const profileResult = await apiRequest('/profile', {
      method: 'PATCH',
      body: profilePayload,
    });
    syncUiWithUser(normalizeUserPayload(profileResult));

    if (state.user?.email !== email) {
      const emailResult = await apiRequest('/email', {
        method: 'PATCH',
        body: { email },
      });
      syncUiWithUser(normalizeUserPayload(emailResult));
    }

    markFormClean(dom.profileForm);
    showToast('Profile updated.', 'success');
    setSyncStatus(new Date());
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.profileSaveBtn, false);
  }
};

const handleLinkedSave = async (event) => {
  event.preventDefault();

  setButtonBusy(dom.linkedSaveBtn, true, 'Saving...');

  try {
    const data = await apiRequest('/linked', {
      method: 'PATCH',
      body: {
        google: safeText(dom.linkedGoogle?.value),
        facebook: safeText(dom.linkedFacebook?.value),
        github: safeText(dom.linkedGithub?.value),
        twitter: safeText(dom.linkedTwitter?.value),
        linkedin: safeText(dom.linkedLinkedin?.value),
        discord: safeText(dom.linkedDiscord?.value),
        apple: safeText(dom.linkedApple?.value),
        microsoft: safeText(dom.linkedMicrosoft?.value),
      },
    });

    syncUiWithUser(normalizeUserPayload(data));
    markFormClean(dom.linkedForm);
    showToast('External profiles updated.', 'success');
    setSyncStatus(new Date());
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.linkedSaveBtn, false);
  }
};

const handlePasswordSave = async (event) => {
  event.preventDefault();

  const currentPassword = dom.currentPassword?.value || '';
  const newPassword = dom.newPassword?.value || '';
  const confirmPassword = dom.confirmPassword?.value || '';

  if (newPassword !== confirmPassword) {
    showToast('New password and confirmation do not match.', 'error');
    return;
  }

  setButtonBusy(dom.passwordSaveBtn, true, 'Updating...');

  try {
    const result = await apiRequest('/password', {
      method: 'PATCH',
      body: { currentPassword, newPassword },
    });

    if (dom.passwordForm) dom.passwordForm.reset();
    updatePasswordStrengthUi();
    showToast(result.message || 'Password updated.', 'success');

    if (result.forceRelogin) {
      clearStoredAuth();
      if (state.refreshTimer) {
        clearInterval(state.refreshTimer);
        state.refreshTimer = null;
      }
      setTimeout(() => setLoggedOutUI(true), 450);
    }
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.passwordSaveBtn, false);
  }
};

const handleSecuritySave = async (event) => {
  event.preventDefault();

  setButtonBusy(dom.securitySaveBtn, true, 'Saving...');

  try {
    const data = await apiRequest('/security', {
      method: 'PATCH',
      body: {
        loginAlerts: Boolean(dom.loginAlertsToggle?.checked),
      },
    });

    syncUiWithUser(normalizeUserPayload(data));
    markFormClean(dom.securityForm);
    showToast('Security settings updated.', 'success');
    setSyncStatus(new Date());
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.securitySaveBtn, false);
  }
};

const buildPreferencesPayload = () => ({
  profilePublic: Boolean(dom.privacyPublic?.checked),
  searchable: Boolean(dom.privacySearchable?.checked),
  notifications: {
    email: Boolean(dom.notifyEmail?.checked),
    sms: Boolean(dom.notifySms?.checked),
    push: Boolean(dom.notifyPush?.checked),
    weeklyDigest: Boolean(dom.notifyWeeklyDigest?.checked),
    security: Boolean(dom.notifySecurity?.checked),
  },
  appearance: {
    theme: safeText(dom.appearanceTheme?.value || 'system'),
    compactMode: Boolean(dom.appearanceCompactMode?.checked),
    reducedMotion: Boolean(dom.appearanceReducedMotion?.checked),
    highContrast: Boolean(dom.appearanceHighContrast?.checked),
    dashboardDensity: safeText(dom.appearanceDensity?.value || 'comfortable'),
  },
});

const savePreferences = async (button, successMessage = 'Preferences saved.') => {
  setButtonBusy(button, true, 'Saving...');

  try {
    const data = await apiRequest('/preferences', {
      method: 'PATCH',
      body: buildPreferencesPayload(),
    });

    syncUiWithUser(normalizeUserPayload(data));
    setDashboardTipsEnabled(Boolean(dom.dashboardTipsToggle?.checked));
    markFormClean(dom.privacyForm);
    markFormClean(dom.notificationForm);
    markFormClean(dom.appearanceForm);
    showToast(successMessage, 'success');
    setSyncStatus(new Date());
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(button, false);
  }
};

const setDashboardTipsEnabled = (enabled) => {
  localStorage.setItem('dashboardTipsEnabled', enabled ? 'true' : 'false');
};

const handleAppearanceReset = async () => {
  if (dom.appearanceTheme) dom.appearanceTheme.value = 'system';
  if (dom.appearanceDensity) dom.appearanceDensity.value = 'comfortable';
  if (dom.appearanceCompactMode) dom.appearanceCompactMode.checked = false;
  if (dom.appearanceReducedMotion) dom.appearanceReducedMotion.checked = false;
  if (dom.appearanceHighContrast) dom.appearanceHighContrast.checked = false;
  if (dom.dashboardTipsToggle) dom.dashboardTipsToggle.checked = true;

  await savePreferences(dom.appearanceResetBtn, 'Appearance reset to defaults.');
};

const handleDeleteAccount = async (event) => {
  event.preventDefault();

  const currentPassword = dom.deletePassword?.value || '';
  const confirmText = safeText(dom.deleteConfirmText?.value).toUpperCase();

  if (confirmText !== 'DELETE') {
    showToast('Type DELETE exactly to confirm account removal.', 'error');
    return;
  }

  if (!window.confirm('Delete your account permanently? This cannot be undone.')) {
    return;
  }

  setButtonBusy(dom.deleteAccountBtn, true, 'Deleting...');

  try {
    await apiRequest('/account', {
      method: 'DELETE',
      body: { currentPassword, confirmText: 'DELETE' },
    });

    if (dom.deleteForm) dom.deleteForm.reset();
    clearStoredAuth();
    if (state.refreshTimer) {
      clearInterval(state.refreshTimer);
      state.refreshTimer = null;
    }

    setLoggedOutUI(false);
    showToast('Account deleted.', 'success');
    openLoginPopup();
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.deleteAccountBtn, false);
  }
};

const runManualRefresh = async () => {
  setButtonBusy(dom.refreshDataBtn, true, 'Refreshing...');

  try {
    await loadDashboardData({ silent: true });
    showToast('Dashboard data refreshed.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.refreshDataBtn, false);
  }
};

const switchTab = (tabId) => {
  for (const btn of dom.tabButtons) {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  }

  for (const panel of dom.tabContents) {
    panel.classList.toggle('active', panel.id === tabId);
  }

  localStorage.setItem(ACTIVE_TAB_STORAGE_KEY, tabId);
};

const setupTabs = () => {
  for (const button of dom.tabButtons) {
    button.addEventListener('click', () => {
      const tabId = safeText(button.dataset.tab);
      if (!tabId) return;
      switchTab(tabId);
    });
  }

  const savedTab = safeText(localStorage.getItem(ACTIVE_TAB_STORAGE_KEY));
  if (savedTab && document.getElementById(savedTab)) {
    switchTab(savedTab);
  }
};

const setupServiceFiltering = () => {
  if (!dom.serviceFilter) return;

  dom.serviceFilter.addEventListener('input', () => {
    const query = safeText(dom.serviceFilter.value).toLowerCase();

    for (const card of dom.serviceCards) {
      const title = safeText(card.dataset.title).toLowerCase();
      card.classList.toggle('hidden', Boolean(query) && !title.includes(query));
    }
  });
};

const isEditableTarget = (target) => {
  if (!target) return false;
  const tag = target.tagName ? target.tagName.toLowerCase() : '';
  return tag === 'input' || tag === 'textarea' || tag === 'select' || target.isContentEditable;
};

const setupKeyboardShortcuts = () => {
  window.addEventListener('keydown', (event) => {
    const isModifier = event.metaKey || event.ctrlKey;
    const key = safeText(event.key).toLowerCase();

    if (isModifier && key === 'k') {
      event.preventDefault();
      dom.serviceFilter?.focus();
      showToast('Service filter focused. Start typing to filter cards.', 'success', 2200);
      return;
    }

    if (isModifier && event.shiftKey && key === 'r') {
      event.preventDefault();
      runManualRefresh();
      return;
    }

    if (!isEditableTarget(event.target) && event.altKey && /^[1-9]$/.test(key)) {
      event.preventDefault();
      const tabIndex = Number(key) - 1;
      const tabButton = dom.tabButtons[tabIndex];
      if (!tabButton?.dataset?.tab) return;
      switchTab(tabButton.dataset.tab);
      return;
    }

    if (!isEditableTarget(event.target) && key === '/') {
      event.preventDefault();
      dom.activityFilter?.focus();
      return;
    }

    if (!isEditableTarget(event.target) && key === '?') {
      event.preventDefault();
      showToast('Shortcuts: Cmd/Ctrl+K filter services, Cmd/Ctrl+Shift+R refresh, Alt+1..9 switch tabs.', 'warn', 5000);
    }
  });
};

const setupEventHandlers = () => {
  setupTabs();
  setupServiceFiltering();
  setupUnsavedChangeTracking();
  setupKeyboardShortcuts();

  if (dom.logoutBtn) dom.logoutBtn.addEventListener('click', doLogout);
  if (dom.refreshDataBtn) dom.refreshDataBtn.addEventListener('click', runManualRefresh);

  if (dom.headerExportJsonBtn) {
    dom.headerExportJsonBtn.addEventListener('click', async () => {
      setButtonBusy(dom.headerExportJsonBtn, true, 'Exporting...');
      try {
        await exportAccountJson();
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.headerExportJsonBtn, false);
      }
    });
  }

  if (dom.profileForm) dom.profileForm.addEventListener('submit', handleProfileSave);
  if (dom.linkedForm) dom.linkedForm.addEventListener('submit', handleLinkedSave);
  if (dom.passwordForm) dom.passwordForm.addEventListener('submit', handlePasswordSave);
  if (dom.securityForm) dom.securityForm.addEventListener('submit', handleSecuritySave);

  if (dom.newPassword) {
    dom.newPassword.addEventListener('input', updatePasswordStrengthUi);
  }

  if (dom.privacyForm) {
    dom.privacyForm.addEventListener('submit', (event) => {
      event.preventDefault();
      savePreferences(dom.privacySaveBtn, 'Privacy settings saved.');
    });
  }

  if (dom.notificationForm) {
    dom.notificationForm.addEventListener('submit', (event) => {
      event.preventDefault();
      savePreferences(dom.notificationSaveBtn, 'Notification preferences saved.');
    });
  }

  if (dom.appearanceForm) {
    dom.appearanceForm.addEventListener('submit', (event) => {
      event.preventDefault();
      savePreferences(dom.appearanceSaveBtn, 'Appearance settings saved.');
    });
  }

  if (dom.appearanceResetBtn) {
    dom.appearanceResetBtn.addEventListener('click', () => {
      handleAppearanceReset();
    });
  }

  if (dom.activityRefreshBtn) {
    dom.activityRefreshBtn.addEventListener('click', async () => {
      setButtonBusy(dom.activityRefreshBtn, true, 'Refreshing...');
      try {
        await loadActivity();
        showToast('Activity refreshed.', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.activityRefreshBtn, false);
      }
    });
  }

  if (dom.activityExportBtn) dom.activityExportBtn.addEventListener('click', exportActivityCsv);
  if (dom.activityFilter) dom.activityFilter.addEventListener('input', renderActivity);

  if (dom.sessionsRefreshBtn) {
    dom.sessionsRefreshBtn.addEventListener('click', async () => {
      setButtonBusy(dom.sessionsRefreshBtn, true, 'Refreshing...');
      try {
        await loadSessions();
        showToast('Sessions refreshed.', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.sessionsRefreshBtn, false);
      }
    });
  }

  if (dom.sessionsRevokeOthersBtn) {
    dom.sessionsRevokeOthersBtn.addEventListener('click', async () => {
      if (!window.confirm('Revoke all other sessions and stay signed in on this device?')) return;

      setButtonBusy(dom.sessionsRevokeOthersBtn, true, 'Revoking...');
      try {
        const data = await apiRequest('/sessions', {
          method: 'DELETE',
          body: { exceptCurrent: true },
        });

        showToast(data.message || 'Other sessions revoked.', 'success');
        await Promise.all([loadSessions(), loadCurrentUser()]);
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.sessionsRevokeOthersBtn, false);
      }
    });
  }

  if (dom.sessionsRevokeAllBtn) {
    dom.sessionsRevokeAllBtn.addEventListener('click', async () => {
      if (!window.confirm('Revoke all sessions? You will need to sign in again.')) return;

      setButtonBusy(dom.sessionsRevokeAllBtn, true, 'Revoking...');
      try {
        const data = await apiRequest('/sessions', {
          method: 'DELETE',
          body: { exceptCurrent: false },
        });

        showToast(data.message || 'Sessions revoked.', 'success');

        if (data.forceRelogin) {
          clearStoredAuth();
          if (state.refreshTimer) {
            clearInterval(state.refreshTimer);
            state.refreshTimer = null;
          }
          setLoggedOutUI(true);
          return;
        }

        await Promise.all([loadSessions(), loadCurrentUser()]);
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.sessionsRevokeAllBtn, false);
      }
    });
  }

  if (dom.deleteForm) dom.deleteForm.addEventListener('submit', handleDeleteAccount);

  window.addEventListener('online', () => {
    setConnectionStatus();
    showToast('Connection restored.', 'success', 2200);
  });

  window.addEventListener('offline', () => {
    setConnectionStatus();
    showToast('You are offline. Some actions may fail.', 'warn', 2800);
  });

  window.addEventListener('beforeunload', (event) => {
    if (!hasUnsavedChanges()) return;
    event.preventDefault();
    event.returnValue = '';
  });

  window.addEventListener('message', async (event) => {
    if (!isTrustedLoginOrigin(event.origin)) return;
    if (!event.data || event.data.type !== 'LOGIN_SUCCESS') return;

    if (event.data.token || event.data.accessToken) {
      storeSession(event.data);
    } else {
      const refreshed = await refreshSession();
      if (!refreshed) {
        showToast('Signed in, but the session could not be established.', 'error');
        return;
      }
    }

    try {
      await loadDashboardData({ silent: true });
      closeLoginPopup();
      showApp();
      showToast('Signed in successfully.', 'success');
    } catch (err) {
      showToast(err.message || 'Could not load account data.', 'error');
    }
  });

  const systemThemeMedia = window.matchMedia('(prefers-color-scheme: dark)');
  if (systemThemeMedia && typeof systemThemeMedia.addEventListener === 'function') {
    systemThemeMedia.addEventListener('change', () => {
      const selectedTheme = safeText(dom.appearanceTheme?.value || 'system').toLowerCase();
      if (selectedTheme === 'system') {
        applyAppearance({
          theme: 'system',
          compactMode: Boolean(dom.appearanceCompactMode?.checked),
          reducedMotion: Boolean(dom.appearanceReducedMotion?.checked),
          highContrast: Boolean(dom.appearanceHighContrast?.checked),
          dashboardDensity: safeText(dom.appearanceDensity?.value || 'comfortable'),
        });
      }
    });
  }
};

const startSessionAutoRefresh = () => {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
  }

  state.refreshTimer = setInterval(async () => {
    const refreshed = await refreshSession();
    if (refreshed) {
      storeSession(refreshed);
      return;
    }

    if (!navigator.onLine) {
      return;
    }

    if (!state.accessToken) {
      clearInterval(state.refreshTimer);
      state.refreshTimer = null;
      return;
    }
  }, REFRESH_INTERVAL_MS);
};

window.addEventListener('load', async () => {
  setConnectionStatus();
  setSyncStatus(null);

  setupEventHandlers();
  updatePasswordStrengthUi();

  const isAuthenticated = await initializeSession();

  if (isAuthenticated) {
    showApp();
    startSessionAutoRefresh();
    return;
  }

  setLoggedOutUI(true);
});
