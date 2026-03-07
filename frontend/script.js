const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1']);
const REFRESH_INTERVAL_MS = 5 * 60 * 1000;

const dom = {
  loadingScreen: document.getElementById('loading-screen'),
  loadingMessage: document.getElementById('loading-message'),
  appContent: document.getElementById('app-content'),
  toastRegion: document.getElementById('toast-region'),
  status: document.getElementById('status'),
  connectionStatus: document.getElementById('connection-status'),
  logoutBtn: document.getElementById('logout-btn'),
  refreshDataBtn: document.getElementById('refresh-data-btn'),
  tabButtons: Array.from(document.querySelectorAll('.tab-btn')),
  tabContents: Array.from(document.querySelectorAll('.tab-content')),

  summaryId: document.getElementById('summary-id'),
  summaryDisplayName: document.getElementById('summary-display-name'),
  summaryLastLogin: document.getElementById('summary-last-login'),
  summary2fa: document.getElementById('summary-2fa'),

  profileForm: document.getElementById('profile-form'),
  profileSaveBtn: document.getElementById('profile-save-btn'),
  profileDisplayName: document.getElementById('profile-display-name'),
  profileEmail: document.getElementById('profile-email'),
  profileId: document.getElementById('profile-id'),
  profileCreated: document.getElementById('profile-created'),

  linkedForm: document.getElementById('linked-form'),
  linkedSaveBtn: document.getElementById('linked-save-btn'),
  linkedGoogle: document.getElementById('linked-google'),
  linkedFacebook: document.getElementById('linked-facebook'),
  linkedGithub: document.getElementById('linked-github'),
  linkedTwitter: document.getElementById('linked-twitter'),

  passwordForm: document.getElementById('password-form'),
  passwordSaveBtn: document.getElementById('password-save-btn'),
  currentPassword: document.getElementById('current-password'),
  newPassword: document.getElementById('new-password'),
  confirmPassword: document.getElementById('confirm-password'),

  securityForm: document.getElementById('security-form'),
  securitySaveBtn: document.getElementById('security-save-btn'),
  twoFaToggle: document.getElementById('two-fa-toggle'),

  privacyForm: document.getElementById('privacy-form'),
  privacySaveBtn: document.getElementById('privacy-save-btn'),
  privacyPublic: document.getElementById('privacy-public'),
  privacySearchable: document.getElementById('privacy-searchable'),

  notificationForm: document.getElementById('notification-form'),
  notificationSaveBtn: document.getElementById('notification-save-btn'),
  notifyEmail: document.getElementById('notify-email'),
  notifySms: document.getElementById('notify-sms'),
  notifyPush: document.getElementById('notify-push'),

  activityList: document.getElementById('activity-list'),
  activityFilter: document.getElementById('activity-filter'),
  activityRefreshBtn: document.getElementById('activity-refresh-btn'),
  activityExportBtn: document.getElementById('activity-export-btn'),

  deleteForm: document.getElementById('delete-form'),
  deleteAccountBtn: document.getElementById('delete-account-btn'),
  deletePassword: document.getElementById('delete-password'),
  deleteConfirmText: document.getElementById('delete-confirm-text'),

  cookiePopup: document.getElementById('cookie-popup'),
  cookieAcceptBtn: document.getElementById('cookie-accept'),
};

const trimTrailingSlash = (value) => String(value || '').replace(/\/+$/, '');

const getDefaultApiBaseUrl = () => {
  if (LOCAL_HOSTS.has(window.location.hostname)) {
    return 'http://localhost:5000';
  }

  if (window.location.hostname === 'mpmc.ddns.net' && window.location.port === '5000') {
    return window.location.origin;
  }

  return 'https://mpmc.ddns.net:5000';
};

const API_BASE_URL = trimTrailingSlash(
  window.__API_BASE_URL__ || localStorage.getItem('apiBaseUrl') || getDefaultApiBaseUrl()
);
const AUTH_API_BASE = `${API_BASE_URL}/api/auth`;

const DEFAULT_LOGIN_POPUP_URL = 'https://pclaystation.github.io/Login/popup.html';
const LOGIN_POPUP_URL =
  window.__LOGIN_POPUP_URL__ || localStorage.getItem('loginPopupUrl') || DEFAULT_LOGIN_POPUP_URL;

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
  loginPopupWindow: null,
  appVisible: false,
  refreshTimer: null,
};

const safeText = (value) => String(value || '').trim();

const formatDate = (value) => {
  const date = new Date(value || '');
  if (Number.isNaN(date.getTime())) return 'Unavailable';
  return date.toLocaleString();
};

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

const showToast = (message, type = 'success', timeoutMs = 3200) => {
  if (!dom.toastRegion) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  dom.toastRegion.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, timeoutMs);
};

const setStatus = (text, options = {}) => {
  const { clickable = false, onClick = null } = options;
  dom.status.textContent = text;
  dom.status.style.cursor = clickable ? 'pointer' : 'default';
  dom.status.onclick = clickable ? onClick : null;
};

const setConnectionStatus = () => {
  const online = navigator.onLine;
  dom.connectionStatus.textContent = online ? 'Online' : 'Offline';
  dom.connectionStatus.classList.toggle('offline', !online);
};

const clearStoredAuth = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('userId');
};

const storeSession = (data) => {
  const token = data?.accessToken || data?.token;
  const userId = data?.userId || data?.continentalId;

  if (token) localStorage.setItem('token', token);
  if (userId) localStorage.setItem('userId', userId);
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

const openLoginPopup = () => {
  const width = 520;
  const height = 680;
  const left = window.screenX + (window.outerWidth - width) / 2;
  const top = window.screenY + (window.outerHeight - height) / 2;

  if (state.loginPopupWindow && !state.loginPopupWindow.closed) {
    state.loginPopupWindow.focus();
    return state.loginPopupWindow;
  }

  state.loginPopupWindow = window.open(
    LOGIN_POPUP_URL,
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
    return LOCAL_HOSTS.has(parsed.hostname);
  } catch {
    return false;
  }
};

const setLoggedOutUI = (openPopup = true) => {
  clearStoredAuth();
  state.user = null;
  state.activity = [];
  clearDashboardUi();

  setStatus('Not logged in - click to sign in', {
    clickable: true,
    onClick: () => openLoginPopup(),
  });

  dom.logoutBtn.style.display = 'none';

  if (!state.appVisible) {
    if (dom.loadingMessage) {
      dom.loadingMessage.textContent = 'Please sign in to continue.';
    }
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
  const token = params.get('token');
  const userId = params.get('userId') || params.get('continentalId');

  if (!token) return false;

  storeSession({ token, userId });
  history.replaceState({}, '', `${window.location.origin}${window.location.pathname}`);
  return true;
};

const refreshSession = async () => {
  try {
    const res = await fetch(`${AUTH_API_BASE}/refresh_token`, {
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

const apiRequest = async (path, options = {}) => {
  const {
    method = 'GET',
    body = undefined,
    auth = true,
    retryOn401 = true,
  } = options;

  const headers = { 'Content-Type': 'application/json' };
  if (auth) {
    const token = localStorage.getItem('token');
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }

  const response = await fetch(`${AUTH_API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'include',
  });

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

const fillSummary = (user) => {
  dom.summaryId.textContent = user.continentalId || user.userId || '-';
  dom.summaryDisplayName.textContent = user.displayName || '-';
  dom.summaryLastLogin.textContent = formatDate(user.lastLoginAt);
  dom.summary2fa.textContent = user.security?.twoFactorEnabled ? 'Enabled' : 'Disabled';
};

const fillProfile = (user) => {
  dom.profileDisplayName.value = user.displayName || '';
  dom.profileEmail.value = user.email || '';
  dom.profileId.value = user.continentalId || user.userId || '';
  dom.profileCreated.value = formatDate(user.createdAt);
};

const fillLinkedAccounts = (user) => {
  dom.linkedGoogle.value = user.linkedAccounts?.google || '';
  dom.linkedFacebook.value = user.linkedAccounts?.facebook || '';
  dom.linkedGithub.value = user.linkedAccounts?.github || '';
  dom.linkedTwitter.value = user.linkedAccounts?.twitter || '';
};

const fillPreferences = (user) => {
  const prefs = user.preferences || {};
  const notifications = prefs.notifications || {};

  dom.privacyPublic.checked = Boolean(prefs.profilePublic);
  dom.privacySearchable.checked = Boolean(prefs.searchable);

  dom.notifyEmail.checked = Boolean(notifications.email);
  dom.notifySms.checked = Boolean(notifications.sms);
  dom.notifyPush.checked = Boolean(notifications.push);
};

const fillSecurity = (user) => {
  dom.twoFaToggle.checked = Boolean(user.security?.twoFactorEnabled);
};

const formatActivityLine = (entry) => {
  const at = formatDate(entry.at);
  const ip = safeText(entry.ip) || 'Unknown IP';
  const ua = safeText(entry.userAgent) || 'Unknown browser/device';
  return `${at} - Login from ${ip} (${ua})`;
};

const renderActivity = () => {
  const query = safeText(dom.activityFilter.value).toLowerCase();
  dom.activityList.innerHTML = '';

  const filtered = state.activity.filter((entry) => {
    if (!query) return true;
    return formatActivityLine(entry).toLowerCase().includes(query);
  });

  if (filtered.length === 0) {
    const li = document.createElement('li');
    li.textContent = query
      ? 'No activity items match this filter.'
      : 'No recent login activity found.';
    dom.activityList.appendChild(li);
    return;
  }

  for (const entry of filtered) {
    const li = document.createElement('li');
    li.textContent = formatActivityLine(entry);
    dom.activityList.appendChild(li);
  }
};

const clearDashboardUi = () => {
  dom.summaryId.textContent = '-';
  dom.summaryDisplayName.textContent = '-';
  dom.summaryLastLogin.textContent = '-';
  dom.summary2fa.textContent = 'Disabled';

  dom.profileForm?.reset();
  if (dom.profileId) dom.profileId.value = '';
  if (dom.profileCreated) dom.profileCreated.value = '';
  if (dom.activityFilter) dom.activityFilter.value = '';

  if (dom.activityList) {
    dom.activityList.innerHTML = '<li>No recent login activity found.</li>';
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

  const statusText = `Logged in as: ${user.email || user.displayName || user.userId}`;
  setStatus(statusText, { clickable: false });
  dom.logoutBtn.style.display = 'inline-flex';
};

const loadCurrentUser = async () => {
  const payload = await apiRequest('/me', { method: 'GET', auth: true });
  const user = normalizeUserPayload(payload);

  if (user?.userId) {
    localStorage.setItem('userId', user.userId);
  }

  syncUiWithUser(user);
  return user;
};

const loadActivity = async () => {
  const data = await apiRequest('/activity', { method: 'GET', auth: true });
  state.activity = Array.isArray(data.recentLogins) ? data.recentLogins : [];
  renderActivity();
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
  fillSecurity(state.user);
};

const loadDashboardData = async ({ silent = false } = {}) => {
  if (!silent && dom.loadingMessage) {
    dom.loadingMessage.textContent = 'Loading dashboard...';
  }

  const user = await loadCurrentUser();

  await Promise.all([loadActivity(), loadPreferences(), loadLinkedAccounts(), loadSecurity()]);

  syncUiWithUser(user);
};

const showApp = () => {
  if (state.appVisible) return;
  state.appVisible = true;

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

  const hasToken = Boolean(localStorage.getItem('token'));
  if (!hasToken) {
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
    // local logout still proceeds even if network call fails
  }

  clearStoredAuth();
  state.user = null;
  state.activity = [];
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

  const a = document.createElement('a');
  a.href = url;
  a.download = `continental-activity-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();

  URL.revokeObjectURL(url);
  showToast('Activity exported.', 'success');
};

const handleProfileSave = async (event) => {
  event.preventDefault();

  const displayName = safeText(dom.profileDisplayName.value);
  const email = safeText(dom.profileEmail.value).toLowerCase();

  if (displayName.length < 2) {
    showToast('Display name must be at least 2 characters.', 'error');
    return;
  }

  setButtonBusy(dom.profileSaveBtn, true, 'Saving...');

  try {
    if (state.user?.displayName !== displayName) {
      const profileData = await apiRequest('/profile', {
        method: 'PATCH',
        body: { displayName },
      });
      syncUiWithUser(normalizeUserPayload(profileData));
    }

    if (state.user?.email !== email) {
      const emailData = await apiRequest('/email', {
        method: 'PATCH',
        body: { email },
      });
      syncUiWithUser(normalizeUserPayload(emailData));
    }

    showToast('Profile updated.', 'success');
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
        google: safeText(dom.linkedGoogle.value),
        facebook: safeText(dom.linkedFacebook.value),
        github: safeText(dom.linkedGithub.value),
        twitter: safeText(dom.linkedTwitter.value),
      },
    });

    syncUiWithUser(normalizeUserPayload(data));
    showToast('Linked accounts updated.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.linkedSaveBtn, false);
  }
};

const handlePasswordSave = async (event) => {
  event.preventDefault();

  const currentPassword = dom.currentPassword.value;
  const newPassword = dom.newPassword.value;
  const confirmPassword = dom.confirmPassword.value;

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

    dom.passwordForm.reset();
    showToast(result.message || 'Password updated.', 'success');

    if (result.forceRelogin) {
      clearStoredAuth();
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
        twoFactorEnabled: Boolean(dom.twoFaToggle.checked),
      },
    });

    syncUiWithUser(normalizeUserPayload(data));
    showToast('Security settings updated.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.securitySaveBtn, false);
  }
};

const buildPreferencesPayload = () => ({
  profilePublic: Boolean(dom.privacyPublic.checked),
  searchable: Boolean(dom.privacySearchable.checked),
  notifications: {
    email: Boolean(dom.notifyEmail.checked),
    sms: Boolean(dom.notifySms.checked),
    push: Boolean(dom.notifyPush.checked),
  },
});

const savePreferences = async (button) => {
  setButtonBusy(button, true, 'Saving...');

  try {
    const data = await apiRequest('/preferences', {
      method: 'PATCH',
      body: buildPreferencesPayload(),
    });

    syncUiWithUser(normalizeUserPayload(data));
    showToast('Preferences saved.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(button, false);
  }
};

const handleDeleteAccount = async (event) => {
  event.preventDefault();

  const currentPassword = dom.deletePassword.value;
  const confirmText = safeText(dom.deleteConfirmText.value).toUpperCase();

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

    dom.deleteForm.reset();
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

const setupTabs = () => {
  for (const button of dom.tabButtons) {
    button.addEventListener('click', () => {
      for (const btn of dom.tabButtons) {
        btn.classList.remove('active');
      }
      for (const panel of dom.tabContents) {
        panel.classList.remove('active');
      }

      button.classList.add('active');
      const tabId = button.dataset.tab;
      const panel = document.getElementById(tabId);
      if (panel) {
        panel.classList.add('active');
      }
    });
  }
};

const setupEventHandlers = () => {
  setupTabs();

  dom.logoutBtn.addEventListener('click', doLogout);
  dom.refreshDataBtn.addEventListener('click', runManualRefresh);

  dom.profileForm.addEventListener('submit', handleProfileSave);
  dom.linkedForm.addEventListener('submit', handleLinkedSave);
  dom.passwordForm.addEventListener('submit', handlePasswordSave);
  dom.securityForm.addEventListener('submit', handleSecuritySave);

  dom.privacyForm.addEventListener('submit', (event) => {
    event.preventDefault();
    savePreferences(dom.privacySaveBtn);
  });

  dom.notificationForm.addEventListener('submit', (event) => {
    event.preventDefault();
    savePreferences(dom.notificationSaveBtn);
  });

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

  dom.activityExportBtn.addEventListener('click', exportActivityCsv);
  dom.activityFilter.addEventListener('input', renderActivity);

  dom.deleteForm.addEventListener('submit', handleDeleteAccount);

  window.addEventListener('online', () => {
    setConnectionStatus();
    showToast('Connection restored.', 'success', 2200);
  });

  window.addEventListener('offline', () => {
    setConnectionStatus();
    showToast('You are offline. Some actions may fail.', 'warn', 2800);
  });

  window.addEventListener('message', async (event) => {
    if (!isTrustedLoginOrigin(event.origin)) return;
    if (!event.data || event.data.type !== 'LOGIN_SUCCESS' || !event.data.token) return;

    storeSession(event.data);

    try {
      await loadDashboardData({ silent: true });
      closeLoginPopup();
      showApp();
      showToast('Signed in successfully.', 'success');
    } catch (err) {
      showToast(err.message || 'Could not load account data.', 'error');
    }
  });
};

const startSessionAutoRefresh = () => {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
  }

  state.refreshTimer = setInterval(async () => {
    const refreshed = await refreshSession();
    if (refreshed) {
      storeSession(refreshed);
    }
  }, REFRESH_INTERVAL_MS);
};

window.addEventListener('load', async () => {
  setConnectionStatus();
  setupEventHandlers();

  const isAuthenticated = await initializeSession();

  if (isAuthenticated) {
    showApp();
    startSessionAutoRefresh();
    return;
  }

  setLoggedOutUI(true);
});
