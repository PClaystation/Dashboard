const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1']);
const REFRESH_INTERVAL_MS = 5 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 15_000;
const ACTIVE_TAB_STORAGE_KEY = 'dashboard.activeTab';
const SERVICE_FAVORITES_STORAGE_KEY = 'dashboard.serviceFavorites';
const FAVORITE_SERVICES_ONLY_STORAGE_KEY = 'dashboard.favoriteServicesOnly';
const OVERVIEW_ACTIVITY_LIMIT = 4;
const AVATAR_UPLOAD_MAX_FILE_BYTES = 5 * 1024 * 1024;
const AVATAR_UPLOAD_MAX_DIMENSION = 256;
const AVATAR_DATA_URL_MAX_LENGTH = 350000;
const AVATAR_ALLOWED_MIME_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif']);

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

  heroInitials: document.getElementById('hero-initials'),
  heroDisplayName: document.getElementById('hero-display-name'),
  heroUsername: document.getElementById('hero-username'),
  heroEmail: document.getElementById('hero-email'),
  heroGreeting: document.getElementById('hero-greeting'),
  heroStatusNote: document.getElementById('hero-status-note'),
  healthScoreValue: document.getElementById('health-score-value'),
  healthScoreLabel: document.getElementById('health-score-label'),
  actionCenter: document.getElementById('action-center'),
  overviewActivityList: document.getElementById('overview-activity-list'),
  overviewJumpProfileBtn: document.getElementById('overview-jump-profile-btn'),
  overviewJumpSecurityBtn: document.getElementById('overview-jump-security-btn'),
  overviewJumpActivityBtn: document.getElementById('overview-jump-activity-btn'),
  profileChecklist: document.getElementById('profile-checklist'),

  summaryId: document.getElementById('summary-id'),
  summaryUsername: document.getElementById('summary-username'),
  summaryDisplayName: document.getElementById('summary-display-name'),
  summaryHeadline: document.getElementById('summary-headline'),
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
  profileUsername: document.getElementById('profile-username'),
  profileDisplayName: document.getElementById('profile-display-name'),
  profilePronouns: document.getElementById('profile-pronouns'),
  profileHeadline: document.getElementById('profile-headline'),
  profileEmail: document.getElementById('profile-email'),
  profileEmailCurrentPassword: document.getElementById('profile-email-current-password'),
  profileAvatarPreview: document.getElementById('profile-avatar-preview'),
  profileAvatarHelper: document.getElementById('profile-avatar-helper'),
  profileAvatarUrl: document.getElementById('profile-avatar-url'),
  profileAvatarUpload: document.getElementById('profile-avatar-upload'),
  profileAvatarUploadBtn: document.getElementById('profile-avatar-upload-btn'),
  profileAvatarRemoveBtn: document.getElementById('profile-avatar-remove-btn'),
  profileLocation: document.getElementById('profile-location'),
  profileWebsite: document.getElementById('profile-website'),
  profileTimezone: document.getElementById('profile-timezone'),
  profileLanguage: document.getElementById('profile-language'),
  profileBio: document.getElementById('profile-bio'),
  profileId: document.getElementById('profile-id'),
  profileCreated: document.getElementById('profile-created'),
  profilePublicLink: document.getElementById('profile-public-link'),
  openPublicProfileBtn: document.getElementById('open-public-profile-btn'),
  profileProgressBar: document.getElementById('profile-progress-bar'),
  profileProgressBars: Array.from(document.querySelectorAll('.profile-progress-fill')),
  profileProgressLabel: document.getElementById('profile-progress-label'),
  verificationPanel: document.getElementById('verification-panel'),
  verificationHelper: document.getElementById('verification-helper'),
  verificationResendBtn: document.getElementById('verification-resend-btn'),

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
  mfaStatusCopy: document.getElementById('mfa-status-copy'),
  mfaSetupBtn: document.getElementById('mfa-setup-btn'),
  mfaDisableBtn: document.getElementById('mfa-disable-btn'),
  mfaBackupBtn: document.getElementById('mfa-backup-btn'),
  mfaSetupPanel: document.getElementById('mfa-setup-panel'),
  mfaCurrentPassword: document.getElementById('mfa-current-password'),
  mfaSecret: document.getElementById('mfa-secret'),
  mfaOtpAuthUrl: document.getElementById('mfa-otpauth-url'),
  mfaCode: document.getElementById('mfa-code'),
  mfaEnableBtn: document.getElementById('mfa-enable-btn'),
  mfaBackupCodes: document.getElementById('mfa-backup-codes'),

  privacyForm: document.getElementById('privacy-form'),
  privacySaveBtn: document.getElementById('privacy-save-btn'),
  privacyPublic: document.getElementById('privacy-public'),
  privacySearchable: document.getElementById('privacy-searchable'),
  publicFieldHeadline: document.getElementById('public-field-headline'),
  publicFieldBio: document.getElementById('public-field-bio'),
  publicFieldPronouns: document.getElementById('public-field-pronouns'),
  publicFieldLocation: document.getElementById('public-field-location'),
  publicFieldWebsite: document.getElementById('public-field-website'),
  publicFieldTimezone: document.getElementById('public-field-timezone'),
  publicFieldLanguage: document.getElementById('public-field-language'),
  publicFieldLinked: document.getElementById('public-field-linked'),
  publicFieldMemberSince: document.getElementById('public-field-member-since'),
  publicProfilePreviewBtn: document.getElementById('public-profile-preview-btn'),
  publicProfileDirectoryBtn: document.getElementById('public-profile-directory-btn'),

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
  devicesList: document.getElementById('devices-list'),
  devicesRefreshBtn: document.getElementById('devices-refresh-btn'),

  activityList: document.getElementById('activity-list'),
  activityKind: document.getElementById('activity-kind'),
  activityFilter: document.getElementById('activity-filter'),
  activityRefreshBtn: document.getElementById('activity-refresh-btn'),
  activityExportBtn: document.getElementById('activity-export-btn'),
  activityBars: document.getElementById('activity-bars'),

  deleteForm: document.getElementById('delete-form'),
  deleteAccountBtn: document.getElementById('delete-account-btn'),
  deletePassword: document.getElementById('delete-password'),
  deleteConfirmText: document.getElementById('delete-confirm-text'),

  serviceFilter: document.getElementById('service-filter'),
  serviceList: document.getElementById('service-list'),
  serviceCards: Array.from(document.querySelectorAll('#service-list .card')),
  serviceResultsCount: document.getElementById('service-results-count'),
  serviceEmptyState: document.getElementById('service-empty-state'),
  favoriteFilterBtn: document.getElementById('favorite-filter-btn'),

  cookiePopup: document.getElementById('cookie-popup'),
  cookieAcceptBtn: document.getElementById('cookie-accept'),
};

const trimTrailingSlash = (value) => String(value || '').replace(/\/+$/, '');
const safeText = (value) => String(value || '').trim();
const readStoredArray = (key) => {
  try {
    const parsed = JSON.parse(localStorage.getItem(key) || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

const writeStoredArray = (key, values) => {
  localStorage.setItem(key, JSON.stringify(values));
};

const normalizeActivitySummary = (summary = {}) => ({
  last7Days: Number(summary?.last7Days || 0),
  last30Days: Number(summary?.last30Days || 0),
  uniqueIps: Number(summary?.uniqueIps || 0),
  recentDays: Array.isArray(summary?.recentDays) ? summary.recentDays : [],
});

const normalizePublicProfileSettings = (settings = {}) => ({
  headline: Boolean(settings?.headline),
  bio: Boolean(settings?.bio),
  pronouns: Boolean(settings?.pronouns),
  location: Boolean(settings?.location),
  website: Boolean(settings?.website),
  timezone: Boolean(settings?.timezone),
  language: Boolean(settings?.language),
  linkedAccounts: Boolean(settings?.linkedAccounts),
  memberSince: Boolean(settings?.memberSince),
});

const normalizeMfaState = (mfa = {}) => ({
  enabled: Boolean(mfa?.enabled),
  hasPendingSetup: Boolean(mfa?.hasPendingSetup),
  enrolledAt: mfa?.enrolledAt || null,
  lastUsedAt: mfa?.lastUsedAt || null,
  backupCodesRemaining: Number(mfa?.backupCodesRemaining || 0),
});

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

  return 'https://grimoire.continental-hub.com/login/popup.html';
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

const buildLoginPopupUrl = () => {
  const popupUrl = new URL(LOGIN_POPUP_URL, window.location.href);
  popupUrl.searchParams.set('origin', window.location.origin);
  popupUrl.searchParams.set('redirect', window.location.href);
  popupUrl.searchParams.set('apiBaseUrl', API_BASE_URL);
  return popupUrl;
};

const state = {
  user: null,
  activity: [],
  auditEvents: [],
  activitySummary: {
    last7Days: 0,
    last30Days: 0,
    uniqueIps: 0,
    recentDays: [],
  },
  sessions: [],
  devices: [],
  sessionLimit: null,
  accessToken: '',
  authEpoch: 0,
  loginPopupWindow: null,
  appVisible: false,
  refreshTimer: null,
  refreshPromise: null,
  lastSyncAt: null,
  favoriteServices: new Set(readStoredArray(SERVICE_FAVORITES_STORAGE_KEY)),
  favoriteServicesOnly: localStorage.getItem(FAVORITE_SERVICES_ONLY_STORAGE_KEY) === 'true',
  profileAvatarDraft: '',
  mfaSetup: null,
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
const persistServicePreferences = () => {
  writeStoredArray(SERVICE_FAVORITES_STORAGE_KEY, Array.from(state.favoriteServices).sort());
  localStorage.setItem(
    FAVORITE_SERVICES_ONLY_STORAGE_KEY,
    state.favoriteServicesOnly ? 'true' : 'false'
  );
};

const getActiveSessionCount = () =>
  Number(state.user?.security?.activeSessions ?? state.sessions.length ?? 0);

const updateSessionNote = () => {
  if (!dom.sessionLimitNote) return;

  const limitText = state.sessionLimit ? `${state.sessionLimit}` : '--';
  const knownDevices = Number(state.user?.security?.knownDevices || 0);
  dom.sessionLimitNote.textContent = knownDevices
    ? `Session limit: ${limitText} | Known devices: ${knownDevices}`
    : `Session limit: ${limitText}`;
};

const getUsername = (user = state.user) => safeText(user?.username).toLowerCase();
const getUserHandle = (user = state.user) => {
  const username = getUsername(user);
  return username ? `@${username}` : '';
};
const getAvatarValue = (user = state.user) => safeText(user?.profile?.avatar);

const getIdentityName = (user = state.user) =>
  safeText(user?.displayName || getUsername(user) || user?.email || user?.continentalId || user?.userId || 'Continental User');

const getIdentityInitials = (user = state.user) => {
  const source = getIdentityName(user);
  const parts = source
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2);

  if (!parts.length) return 'CI';
  return parts.map((part) => part[0].toUpperCase()).join('');
};

const getFirstName = (user = state.user) => {
  const source = safeText(user?.displayName || getUsername(user) || user?.email || 'there');
  return source.split(/[\s@._-]+/).filter(Boolean)[0] || 'there';
};

const normalizeAvatarInput = (value) => {
  const raw = safeText(value);
  if (!raw) return '';

  if (/^data:image\/(?:png|jpe?g|gif|webp);base64,[a-z0-9+/=]+$/i.test(raw)) {
    return raw.length <= AVATAR_DATA_URL_MAX_LENGTH ? raw : null;
  }

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

const setAvatarElement = (element, avatarValue, fallbackText) => {
  if (!element) return;

  const normalized = normalizeAvatarInput(avatarValue);
  const hasAvatar = Boolean(normalized);

  element.textContent = fallbackText;
  element.classList.toggle('has-image', hasAvatar);
  element.style.backgroundImage = hasAvatar ? `url(${JSON.stringify(normalized)})` : '';
};

const updateProfileAvatarHelper = (avatarValue = state.profileAvatarDraft) => {
  if (!dom.profileAvatarHelper) return;

  if (!avatarValue) {
    dom.profileAvatarHelper.textContent =
      'Upload an image or paste a direct image URL. Uploaded images are resized before saving.';
    return;
  }

  const normalized = normalizeAvatarInput(avatarValue);
  if (!normalized) {
    dom.profileAvatarHelper.textContent = 'Avatar must be a direct image URL or an uploaded image.';
    return;
  }

  if (String(normalized).startsWith('data:image/')) {
    dom.profileAvatarHelper.textContent =
      'Uploaded image ready. It will be saved to your account when you save the profile.';
    return;
  }

  dom.profileAvatarHelper.textContent = 'External avatar URL ready. Save the profile to apply it.';
};

const renderAvatarPreviews = (user = state.user) => {
  const fallbackText = getIdentityInitials(user);
  const heroAvatar = getAvatarValue(user);
  const profileAvatar = state.profileAvatarDraft;

  setAvatarElement(dom.heroInitials, heroAvatar, fallbackText);
  setAvatarElement(dom.profileAvatarPreview, profileAvatar, fallbackText);
  updateProfileAvatarHelper(profileAvatar);
};

const resetProfileAvatarDraft = (user = state.user) => {
  const avatar = getAvatarValue(user);
  state.profileAvatarDraft = avatar;

  if (dom.profileAvatarUrl) {
    dom.profileAvatarUrl.value = avatar && !String(avatar).startsWith('data:image/') ? avatar : '';
  }

  if (dom.profileAvatarUpload) {
    dom.profileAvatarUpload.value = '';
  }

  renderAvatarPreviews(user);
};

const setProfileProgress = (completion) => {
  const percentage = `${Number(completion || 0)}%`;

  for (const bar of dom.profileProgressBars) {
    if (bar) bar.style.width = percentage;
  }

  if (dom.profileProgressLabel) dom.profileProgressLabel.textContent = percentage;
  if (dom.summaryCompletion) dom.summaryCompletion.textContent = percentage;
};

const computeAccountHealth = (user = state.user) => {
  if (!user) {
    return {
      score: 0,
      label: 'Signed out',
      description: 'Sign in to load account health.',
    };
  }

  const completion = Number(user.profile?.completion || 0);
  const activeSessions = Math.max(1, getActiveSessionCount());
  let score = Math.min(45, Math.round(completion * 0.45));

  if (user.isVerified) score += 20;
  if (user.security?.loginAlerts) score += 15;
  if (user.security?.mfa?.enabled) score += 18;
  if (getUsername(user)) score += 6;
  if (getAvatarValue(user)) score += 5;
  if (safeText(user.profile?.headline)) score += 4;
  if (safeText(user.profile?.timezone)) score += 8;
  if (safeText(user.profile?.website)) score += 5;
  score += activeSessions <= 1 ? 10 : Math.max(0, 10 - (activeSessions - 1) * 3);

  const boundedScore = Math.max(0, Math.min(100, score));

  if (boundedScore >= 85) {
    return {
      score: boundedScore,
      label: 'Strong',
      description: 'Profile and security settings look well maintained.',
    };
  }

  if (boundedScore >= 65) {
    return {
      score: boundedScore,
      label: 'Healthy',
      description: 'A few details could still be tightened up.',
    };
  }

  if (boundedScore >= 45) {
    return {
      score: boundedScore,
      label: 'Needs review',
      description: 'There are a couple of obvious cleanup items.',
    };
  }

  return {
    score: boundedScore,
    label: 'At risk',
    description: 'Important setup steps are still missing.',
  };
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
  state.authEpoch += 1;
};

const stopSessionAutoRefresh = () => {
  if (!state.refreshTimer) return;
  clearInterval(state.refreshTimer);
  state.refreshTimer = null;
};

const handleUnauthenticatedState = ({
  openPopup = true,
  message = 'Your session expired. Please sign in again.',
  notify = true,
} = {}) => {
  const shouldResetUi = Boolean(state.appVisible || state.user || state.accessToken);

  stopSessionAutoRefresh();
  clearStoredAuth();

  if (!shouldResetUi) {
    return;
  }

  setLoggedOutUI(openPopup);

  if (notify && message && state.appVisible) {
    showToast(message, 'warn', 4200);
  }
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
  const width = 860;
  const height = 780;
  const left = window.screenX + (window.outerWidth - width) / 2;
  const top = window.screenY + (window.outerHeight - height) / 2;
  const popupUrl = buildLoginPopupUrl();

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

const openLoginPage = () => {
  window.location.assign(buildLoginPopupUrl().toString());
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
  state.auditEvents = [];
  state.activitySummary = normalizeActivitySummary();
  state.sessions = [];
  state.devices = [];
  state.sessionLimit = null;
  state.profileAvatarDraft = '';
  state.mfaSetup = null;

  if (dom.summaryId) dom.summaryId.textContent = '-';
  if (dom.summaryUsername) dom.summaryUsername.textContent = '-';
  if (dom.summaryDisplayName) dom.summaryDisplayName.textContent = '-';
  if (dom.summaryHeadline) dom.summaryHeadline.textContent = '-';
  if (dom.summaryLastLogin) dom.summaryLastLogin.textContent = '-';
  if (dom.summaryVerified) dom.summaryVerified.textContent = 'Pending';
  if (dom.summarySessions) dom.summarySessions.textContent = '0';
  setProfileProgress(0);
  renderHero(null);
  renderAccountHealth(null);

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
  if (dom.profilePublicLink) dom.profilePublicLink.value = '';
  if (dom.openPublicProfileBtn) dom.openPublicProfileBtn.disabled = true;
  if (dom.profileAvatarUrl) dom.profileAvatarUrl.value = '';
  if (dom.profileAvatarUpload) dom.profileAvatarUpload.value = '';
  if (dom.mfaCurrentPassword) dom.mfaCurrentPassword.value = '';
  if (dom.mfaCode) dom.mfaCode.value = '';

  if (dom.activityFilter) dom.activityFilter.value = '';
  if (dom.activityKind) dom.activityKind.value = 'all';
  if (dom.serviceFilter) dom.serviceFilter.value = '';
  if (dom.activityList) dom.activityList.innerHTML = '<li>No recent login activity found.</li>';
  if (dom.overviewActivityList) dom.overviewActivityList.innerHTML = '<li>Recent login activity will appear here.</li>';
  if (dom.sessionsList) dom.sessionsList.innerHTML = '<li>No active sessions found.</li>';
  if (dom.devicesList) dom.devicesList.innerHTML = '<li>No known devices found.</li>';
  if (dom.activityBars) dom.activityBars.innerHTML = '';
  renderBackupCodes([]);
  renderMfaState();

  if (dom.insightLast7) dom.insightLast7.textContent = '0';
  if (dom.insightLast30) dom.insightLast30.textContent = '0';
  if (dom.insightIps) dom.insightIps.textContent = '0';
  if (dom.sessionLimitNote) dom.sessionLimitNote.textContent = 'Session limit: --';
  renderVerificationState();
  renderActionCenter(null);
  renderProfileChecklist(null);
  renderServices();
  renderAvatarPreviews(null);

  applyAppearance({
    theme: 'system',
    compactMode: false,
    reducedMotion: false,
    highContrast: false,
    dashboardDensity: 'comfortable',
  });
};

const setLoggedOutUI = (openPopup = true) => {
  stopSessionAutoRefresh();
  clearStoredAuth();
  clearDashboardUi();

  setStatus('Not logged in - click to sign in', {
    clickable: true,
    onClick: () => {
      const popup = openLoginPopup();
      if (!popup) {
        openLoginPage();
      }
    },
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
    dom.loadingMessage.textContent = 'Login popup blocked. Click here to continue to login.';
  }

  if (dom.loadingScreen) {
    dom.loadingScreen.style.cursor = 'pointer';
    dom.loadingScreen.onclick = () => {
      openLoginPage();
    };
  }
};

const stripLegacyAuthParamsFromUrl = () => {
  const params = new URLSearchParams(window.location.search);
  const hadLegacyAuthParams =
    params.has('token') || params.has('userId') || params.has('continentalId');

  if (hadLegacyAuthParams) {
    params.delete('token');
    params.delete('userId');
    params.delete('continentalId');
    const nextQuery = params.toString();
    const nextUrl = `${window.location.pathname}${nextQuery ? `?${nextQuery}` : ''}${window.location.hash}`;
    history.replaceState({}, '', nextUrl);
  }
};

const refreshSession = async () => {
  if (state.refreshPromise) {
    return state.refreshPromise;
  }

  state.refreshPromise = (async () => {
    const authEpoch = state.authEpoch;

    try {
      const res = await fetchWithTimeout(`${AUTH_API_BASE}/refresh_token`, {
        method: 'POST',
        credentials: 'include',
      });

      const data = await parseResponseBody(res);
      if (!res.ok) {
        return {
          ok: false,
          reason: res.status === 401 ? 'unauthenticated' : 'error',
          message: data.message || 'Session refresh failed.',
        };
      }

      if (!(data.accessToken || data.token)) {
        return {
          ok: false,
          reason: data.authenticated === false ? 'unauthenticated' : 'error',
          message: data.message || 'Session refresh failed.',
        };
      }

      if (state.authEpoch !== authEpoch) {
        return { ok: false, reason: 'stale', message: '' };
      }

      storeSession(data);
      return { ok: true, data };
    } catch (error) {
      return {
        ok: false,
        reason:
          error?.name === 'AbortError'
            ? 'timeout'
            : error instanceof TypeError
              ? 'network'
              : 'error',
        message: '',
      };
    } finally {
      state.refreshPromise = null;
    }
  })();

  return state.refreshPromise;
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
    if (refreshed.ok) {
      return apiRequest(path, { method, body, auth, retryOn401: false });
    }

    if (refreshed.reason === 'unauthenticated') {
      handleUnauthenticatedState({
        message: refreshed.message || 'Your session expired. Please sign in again.',
      });
      throw new Error(refreshed.message || 'Your session expired. Please sign in again.');
    }
  }

  const payload = await parseResponseBody(response);

  if (!response.ok) {
    if (response.status === 401 && auth) {
      handleUnauthenticatedState({
        message: payload.message || 'Your session expired. Please sign in again.',
      });
    }
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

const loadImageFromDataUrl = (dataUrl) =>
  new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error('Selected image could not be loaded.'));
    image.src = dataUrl;
  });

const readFileAsDataUrl = (file) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => reject(new Error('Selected file could not be read.'));
    reader.readAsDataURL(file);
  });

const compressAvatarFile = async (file) => {
  if (!file) {
    throw new Error('Select an image to upload.');
  }

  if (!AVATAR_ALLOWED_MIME_TYPES.has(file.type)) {
    throw new Error('Avatar must be a PNG, JPG, GIF, or WebP image.');
  }

  if (file.size > AVATAR_UPLOAD_MAX_FILE_BYTES) {
    throw new Error('Avatar image is too large. Use a file under 5 MB.');
  }

  const rawDataUrl = await readFileAsDataUrl(file);
  const image = await loadImageFromDataUrl(rawDataUrl);
  const scale = Math.min(1, AVATAR_UPLOAD_MAX_DIMENSION / Math.max(image.width, image.height, 1));
  const width = Math.max(1, Math.round(image.width * scale));
  const height = Math.max(1, Math.round(image.height * scale));

  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;

  const context = canvas.getContext('2d');
  if (!context) {
    throw new Error('Avatar processing is not available in this browser.');
  }

  context.drawImage(image, 0, 0, width, height);

  let compressed = canvas.toDataURL('image/webp', 0.82);
  if (compressed.length > AVATAR_DATA_URL_MAX_LENGTH) {
    compressed = canvas.toDataURL('image/jpeg', 0.8);
  }

  if (compressed.length > AVATAR_DATA_URL_MAX_LENGTH) {
    throw new Error('Avatar image is still too large after resizing. Try a smaller source image.');
  }

  return compressed;
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

const renderHero = (user = state.user) => {
  if (dom.heroDisplayName) dom.heroDisplayName.textContent = getIdentityName(user);
  if (dom.heroUsername) dom.heroUsername.textContent = getUserHandle(user) || '@continental';
  if (dom.heroEmail) dom.heroEmail.textContent = safeText(user?.email) || 'Signed-out session';
  if (dom.heroGreeting) {
    dom.heroGreeting.textContent = user ? `Welcome back, ${getFirstName(user)}` : 'Welcome back';
  }

  if (dom.heroStatusNote) {
    if (!user) {
      dom.heroStatusNote.textContent = 'Finish your setup to keep your account in good shape.';
      return;
    }

    const completion = Number(user.profile?.completion || 0);
    const sessionCount = Math.max(0, getActiveSessionCount());
    dom.heroStatusNote.textContent = `${completion}% complete, ${
      user.isVerified ? 'email verified' : 'verification pending'
    }, ${sessionCount} active ${sessionCount === 1 ? 'session' : 'sessions'}.`;
  }

  renderAvatarPreviews(user);
};

const renderAccountHealth = (user = state.user) => {
  const health = computeAccountHealth(user);
  if (dom.healthScoreValue) dom.healthScoreValue.textContent = String(health.score);
  if (dom.healthScoreLabel) dom.healthScoreLabel.textContent = `${health.label}. ${health.description}`;
};

const renderInsights = () => {
  if (dom.insightLast7) dom.insightLast7.textContent = String(state.activitySummary.last7Days || 0);
  if (dom.insightLast30) dom.insightLast30.textContent = String(state.activitySummary.last30Days || 0);
  if (dom.insightIps) dom.insightIps.textContent = String(state.activitySummary.uniqueIps || 0);
  if (dom.insightVerified) dom.insightVerified.textContent = state.user?.isVerified ? 'Verified' : 'Pending';
};

const renderVerificationState = (user = state.user) => {
  if (!user) {
    if (dom.summaryVerified) dom.summaryVerified.textContent = 'Pending';
    if (dom.insightVerified) dom.insightVerified.textContent = 'Pending';
    if (dom.verificationPanel) dom.verificationPanel.hidden = true;
    if (dom.verificationHelper) {
      dom.verificationHelper.textContent = 'Your email address is still pending verification.';
    }
    return;
  }

  const isVerified = Boolean(user?.isVerified);

  if (dom.summaryVerified) dom.summaryVerified.textContent = isVerified ? 'Verified' : 'Pending';
  if (dom.insightVerified) dom.insightVerified.textContent = isVerified ? 'Verified' : 'Pending';

  if (dom.verificationPanel) {
    dom.verificationPanel.hidden = isVerified;
  }

  if (dom.verificationHelper) {
    const email = safeText(user?.email);
    dom.verificationHelper.textContent = isVerified
      ? 'Your email address is verified.'
      : `Your email address${email ? ` (${email})` : ''} is still pending verification.`;
  }
};

const renderProfileChecklist = (user = state.user) => {
  if (!dom.profileChecklist) return;

  dom.profileChecklist.innerHTML = '';

  if (!isDashboardTipsEnabled()) {
    const li = document.createElement('li');
    li.textContent = 'Helpful dashboard tips are hidden in Appearance settings.';
    dom.profileChecklist.appendChild(li);
    return;
  }

  if (!user) {
    const li = document.createElement('li');
    li.textContent = 'Sign in to load checklist items.';
    dom.profileChecklist.appendChild(li);
    return;
  }

  const items = [
    {
      title: 'Username claimed',
      detail: getUserHandle(user) ? `${getUserHandle(user)} is active.` : 'Choose a sign-in handle.',
      complete: Boolean(getUsername(user)),
    },
    {
      title: 'Display name added',
      detail: safeText(user.displayName) ? 'Looks good.' : 'Add a readable public name.',
      complete: Boolean(safeText(user.displayName)),
    },
    {
      title: 'Profile picture added',
      detail: getAvatarValue(user) ? 'Avatar is set.' : 'Add a picture so your account is easier to recognize.',
      complete: Boolean(getAvatarValue(user)),
    },
    {
      title: 'Headline added',
      detail: safeText(user.profile?.headline) ? 'Headline is set.' : 'Add a short identity tagline.',
      complete: Boolean(safeText(user.profile?.headline)),
    },
    {
      title: 'Email verified',
      detail: user.isVerified ? 'Verification complete.' : 'Verify to reduce lockout risk.',
      complete: Boolean(user.isVerified),
    },
    {
      title: 'Location added',
      detail: safeText(user.profile?.location) ? 'Location is on file.' : 'Add a location for context.',
      complete: Boolean(safeText(user.profile?.location)),
    },
    {
      title: 'Timezone added',
      detail: safeText(user.profile?.timezone) ? 'Timezone is set.' : 'Set a timezone for accurate scheduling.',
      complete: Boolean(safeText(user.profile?.timezone)),
    },
    {
      title: 'Security alerts enabled',
      detail: user.security?.loginAlerts ? 'Login alerts are active.' : 'Turn on suspicious sign-in alerts.',
      complete: Boolean(user.security?.loginAlerts),
    },
    {
      title: 'MFA enabled',
      detail: user.security?.mfa?.enabled ? 'Second-factor protection is active.' : 'Enable MFA to protect sign-in.',
      complete: Boolean(user.security?.mfa?.enabled),
    },
  ];

  for (const item of items) {
    const li = document.createElement('li');
    li.className = item.complete ? 'complete' : 'incomplete';

    const title = document.createElement('strong');
    title.textContent = item.complete ? `${item.title} - done` : item.title;

    const detail = document.createElement('span');
    detail.textContent = item.detail;

    li.appendChild(title);
    li.appendChild(detail);
    dom.profileChecklist.appendChild(li);
  }
};

const createActionItem = ({ tone = 'neutral', title, detail, actionLabel, onAction }) => {
  const item = document.createElement('article');
  item.className = 'action-item';
  item.dataset.tone = tone;

  const content = document.createElement('div');
  const heading = document.createElement('strong');
  heading.textContent = title;
  const body = document.createElement('p');
  body.textContent = detail;

  content.appendChild(heading);
  content.appendChild(body);
  item.appendChild(content);

  if (actionLabel && typeof onAction === 'function') {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = tone === 'danger' ? 'danger-btn' : 'secondary-btn';
    button.textContent = actionLabel;
    button.addEventListener('click', onAction);
    item.appendChild(button);
  }

  return item;
};

const renderActionCenter = (user = state.user) => {
  if (!dom.actionCenter) return;

  dom.actionCenter.innerHTML = '';

  if (!user) {
    dom.actionCenter.appendChild(
      createActionItem({
        tone: 'warn',
        title: 'Sign in required',
        detail: 'Your personalized suggestions will appear once the dashboard loads account data.',
      })
    );
    return;
  }

  const actions = [];
  const completion = Number(user.profile?.completion || 0);
  const activeSessions = Math.max(0, getActiveSessionCount());

  if (!user.isVerified) {
    actions.push({
      tone: 'warn',
      title: 'Verify your email',
      detail: 'Verification is still pending, so recovery and trust signals are weaker than they should be.',
      actionLabel: 'Resend email',
      onAction: () => handleResendVerification(),
    });
  }

  if (completion < 80) {
    actions.push({
      tone: 'neutral',
      title: 'Finish your profile',
      detail: `Your profile is only ${completion}% complete. Fill the remaining details so the account is easier to manage.`,
      actionLabel: 'Open profile',
      onAction: () => switchTab('profile'),
    });
  }

  if (!user.security?.loginAlerts) {
    actions.push({
      tone: 'neutral',
      title: 'Enable login alerts',
      detail: 'Get a heads-up when suspicious sign-in activity is detected.',
      actionLabel: 'Open security',
      onAction: () => switchTab('security'),
    });
  }

  if (!user.security?.mfa?.enabled) {
    actions.push({
      tone: 'warn',
      title: 'Turn on MFA',
      detail: 'Password-only sign-in is still enabled. Add an authenticator app before this account is reused elsewhere.',
      actionLabel: 'Set up MFA',
      onAction: () => switchTab('security'),
    });
  }

  if (!getAvatarValue(user)) {
    actions.push({
      tone: 'neutral',
      title: 'Add a profile picture',
      detail: 'A custom avatar makes the account easier to recognize across sessions and tools.',
      actionLabel: 'Upload avatar',
      onAction: () => switchTab('profile'),
    });
  }

  if (activeSessions > 1) {
    actions.push({
      tone: 'neutral',
      title: 'Review open sessions',
      detail: `${activeSessions} sessions are active right now. Revoke the ones you no longer recognize or need.`,
      actionLabel: 'Review sessions',
      onAction: () => switchTab('security'),
    });
  }

  if (!actions.length) {
    actions.push({
      tone: 'success',
      title: 'Everything looks tidy',
      detail: 'Profile, verification, and session controls are all in a healthy state.',
      actionLabel: 'View activity',
      onAction: () => switchTab('activity'),
    });
  }

  for (const action of actions.slice(0, 4)) {
    dom.actionCenter.appendChild(createActionItem(action));
  }
};

const getPublicProfileUrl = (username = state.user?.username) => {
  const handle = safeText(username);
  if (!handle) return '';

  const url = new URL('profile.html', window.location.href);
  url.searchParams.set('u', handle);
  return url.toString();
};

const updatePublicProfileLink = (user = state.user) => {
  if (!dom.profilePublicLink) return;

  const url = getPublicProfileUrl(user?.username);
  const isPublic = Boolean(user?.preferences?.profilePublic);

  if (!url) {
    dom.profilePublicLink.value = 'Set a username to generate a public profile link.';
  } else if (isPublic) {
    dom.profilePublicLink.value = url;
  } else {
    dom.profilePublicLink.value = `${url} (currently private)`;
  }

  if (dom.openPublicProfileBtn) {
    dom.openPublicProfileBtn.disabled = !url || !isPublic;
  }
};

const fillSummary = (user) => {
  if (dom.summaryId) dom.summaryId.textContent = user.continentalId || user.userId || '-';
  if (dom.summaryUsername) dom.summaryUsername.textContent = getUserHandle(user) || '-';
  if (dom.summaryDisplayName) dom.summaryDisplayName.textContent = user.displayName || '-';
  if (dom.summaryHeadline) dom.summaryHeadline.textContent = safeText(user.profile?.headline) || '-';
  if (dom.summaryLastLogin) dom.summaryLastLogin.textContent = formatDate(user.lastLoginAt);
  if (dom.summarySessions) {
    dom.summarySessions.textContent = String(user.security?.activeSessions ?? state.sessions.length ?? 0);
  }

  const completion = Number(user.profile?.completion || 0);
  setProfileProgress(completion);
  renderHero(user);
  renderAccountHealth(user);
  renderActionCenter(user);
  renderProfileChecklist(user);
};

const fillProfile = (user) => {
  if (dom.profileUsername) dom.profileUsername.value = user.username || '';
  if (dom.profileDisplayName) dom.profileDisplayName.value = user.displayName || '';
  if (dom.profilePronouns) dom.profilePronouns.value = user.profile?.pronouns || '';
  if (dom.profileHeadline) dom.profileHeadline.value = user.profile?.headline || '';
  if (dom.profileEmail) dom.profileEmail.value = user.email || '';
  if (dom.profileEmailCurrentPassword) dom.profileEmailCurrentPassword.value = '';
  if (dom.profileLocation) dom.profileLocation.value = user.profile?.location || '';
  if (dom.profileWebsite) dom.profileWebsite.value = user.profile?.website || '';
  if (dom.profileTimezone) dom.profileTimezone.value = user.profile?.timezone || '';
  if (dom.profileLanguage) dom.profileLanguage.value = user.profile?.language || '';
  if (dom.profileBio) dom.profileBio.value = user.profile?.bio || '';
  if (dom.profileId) dom.profileId.value = user.continentalId || user.userId || '';
  if (dom.profileCreated) dom.profileCreated.value = formatDate(user.createdAt);

  const completion = Number(user.profile?.completion || 0);
  setProfileProgress(completion);
  resetProfileAvatarDraft(user);
  updatePublicProfileLink(user);
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
  const publicProfile = normalizePublicProfileSettings(prefs.publicProfile);

  if (dom.privacyPublic) dom.privacyPublic.checked = Boolean(prefs.profilePublic);
  if (dom.privacySearchable) dom.privacySearchable.checked = Boolean(prefs.searchable);
  if (dom.publicFieldHeadline) dom.publicFieldHeadline.checked = publicProfile.headline;
  if (dom.publicFieldBio) dom.publicFieldBio.checked = publicProfile.bio;
  if (dom.publicFieldPronouns) dom.publicFieldPronouns.checked = publicProfile.pronouns;
  if (dom.publicFieldLocation) dom.publicFieldLocation.checked = publicProfile.location;
  if (dom.publicFieldWebsite) dom.publicFieldWebsite.checked = publicProfile.website;
  if (dom.publicFieldTimezone) dom.publicFieldTimezone.checked = publicProfile.timezone;
  if (dom.publicFieldLanguage) dom.publicFieldLanguage.checked = publicProfile.language;
  if (dom.publicFieldLinked) dom.publicFieldLinked.checked = publicProfile.linkedAccounts;
  if (dom.publicFieldMemberSince) dom.publicFieldMemberSince.checked = publicProfile.memberSince;

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
  updatePublicProfileLink(user);
};

const fillSecurity = (user) => {
  if (dom.loginAlertsToggle) dom.loginAlertsToggle.checked = Boolean(user.security?.loginAlerts);
  renderMfaState(user);
  renderAccountHealth(user);
  renderActionCenter(user);
  renderProfileChecklist(user);
};

const normalizeAuditEvent = (event = {}) => ({
  at: event?.at || null,
  type: safeText(event?.type),
  message: safeText(event?.message),
  ip: safeText(event?.ip),
  userAgent: safeText(event?.userAgent),
  meta:
    event?.meta && typeof event.meta === 'object' && !Array.isArray(event.meta)
      ? event.meta
      : {},
});

const prettifyAuditType = (type) =>
  safeText(type)
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase()) || 'Account event';

const getAuditBucket = (event = {}) => {
  const type = safeText(event?.type).toLowerCase();
  if (
    type.includes('password') ||
    type.includes('security') ||
    type.includes('session') ||
    type.includes('login') ||
    type.includes('email') ||
    type.includes('verification')
  ) {
    return 'security';
  }

  return 'account';
};

const formatActivityLine = (entry) => {
  const at = formatDate(entry.at);
  const ip = safeText(entry.ip) || 'Unknown IP';
  const ua = safeText(entry.userAgent) || 'Unknown browser/device';
  return `${at} - Login from ${ip} (${ua})`;
};

const formatAuditLine = (event) => {
  const auditEvent = normalizeAuditEvent(event);
  const metaText = Object.entries(auditEvent.meta)
    .map(([key, value]) => `${safeText(key)} ${safeText(value)}`)
    .join(' ');

  return [
    formatDate(auditEvent.at),
    auditEvent.type,
    auditEvent.message,
    auditEvent.ip,
    auditEvent.userAgent,
    metaText,
  ]
    .join(' ')
    .toLowerCase();
};

const createLoginActivityListItem = (entry) => {
  const li = document.createElement('li');
  li.className = 'activity-item';

  const head = document.createElement('div');
  head.className = 'activity-head';

  const title = document.createElement('p');
  title.className = 'activity-title';
  title.textContent = `Login from ${safeText(entry.ip) || 'Unknown IP'}`;

  const chip = document.createElement('span');
  chip.className = 'inline-chip';
  chip.textContent = formatDate(entry.at);

  const meta = document.createElement('div');
  meta.className = 'activity-meta';
  meta.textContent = safeText(entry.userAgent) || 'Unknown browser or device';

  head.appendChild(title);
  head.appendChild(chip);
  li.appendChild(head);
  li.appendChild(meta);
  return li;
};

const buildTimelineItems = () => {
  const loginItems = state.activity.map((entry) => ({
    bucket: 'logins',
    chip: 'Login',
    title: `Login from ${safeText(entry.ip) || 'Unknown IP'}`,
    detail: safeText(entry.userAgent) || 'Unknown browser or device',
    at: entry.at,
    searchLine: formatActivityLine(entry).toLowerCase(),
  }));

  const auditItems = state.auditEvents.map((event) => {
    const auditEvent = normalizeAuditEvent(event);
    const metaParts = Object.entries(auditEvent.meta)
      .map(([key, value]) => `${safeText(key)}: ${safeText(value)}`)
      .filter(Boolean);
    const bucket = getAuditBucket(auditEvent);

    return {
      bucket,
      chip: bucket === 'security' ? 'Security' : 'Account',
      title: auditEvent.message || prettifyAuditType(auditEvent.type),
      detail: [auditEvent.ip, auditEvent.userAgent, ...metaParts].filter(Boolean).join(' | '),
      at: auditEvent.at,
      searchLine: formatAuditLine(auditEvent),
    };
  });

  return [...loginItems, ...auditItems].sort((left, right) => {
    const leftTime = new Date(left.at || 0).getTime();
    const rightTime = new Date(right.at || 0).getTime();
    return rightTime - leftTime;
  });
};

const createTimelineListItem = (item) => {
  const li = document.createElement('li');
  li.className = 'activity-item';

  const head = document.createElement('div');
  head.className = 'activity-head';

  const title = document.createElement('p');
  title.className = 'activity-title';
  title.textContent = item.title;

  const chip = document.createElement('span');
  chip.className = 'inline-chip';
  chip.textContent = item.chip;

  const meta = document.createElement('div');
  meta.className = 'activity-meta';
  meta.textContent = [formatDate(item.at), item.detail].filter(Boolean).join(' | ');

  head.appendChild(title);
  head.appendChild(chip);
  li.appendChild(head);
  li.appendChild(meta);
  return li;
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

const renderOverviewActivity = () => {
  if (!dom.overviewActivityList) return;

  dom.overviewActivityList.innerHTML = '';

  const previewItems = state.activity.slice(0, OVERVIEW_ACTIVITY_LIMIT);
  if (!previewItems.length) {
    const li = document.createElement('li');
    li.textContent = 'Recent login activity will appear here.';
    dom.overviewActivityList.appendChild(li);
    return;
  }

  for (const entry of previewItems) {
    dom.overviewActivityList.appendChild(createLoginActivityListItem(entry));
  }
};

const renderActivity = () => {
  if (!dom.activityList) return;

  const query = safeText(dom.activityFilter?.value).toLowerCase();
  const kind = safeText(dom.activityKind?.value).toLowerCase() || 'all';
  dom.activityList.innerHTML = '';

  const filtered = buildTimelineItems().filter((item) => {
    const matchesKind = kind === 'all' ? true : item.bucket === kind;
    const matchesQuery = !query || item.searchLine.includes(query);
    return matchesKind && matchesQuery;
  });

  if (filtered.length === 0) {
    const li = document.createElement('li');
    li.textContent = query || kind !== 'all'
      ? 'No activity items match this filter.'
      : 'No recent activity found.';
    dom.activityList.appendChild(li);
    return;
  }

  for (const item of filtered) {
    dom.activityList.appendChild(createTimelineListItem(item));
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
    const label = document.createElement('strong');
    label.textContent = safeText(session.label) || 'Browser session';
    left.appendChild(label);

    if (session.newDevice || session.recognized) {
      left.appendChild(document.createTextNode(' '));
      const deviceChip = document.createElement('span');
      deviceChip.className = 'inline-chip';
      deviceChip.textContent = session.newDevice ? 'New device' : 'Recognized';
      left.appendChild(deviceChip);
    }

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
          stopSessionAutoRefresh();
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
    meta.textContent = `Last used: ${formatDate(session.lastUsedAt)} | Created: ${formatDate(session.createdAt)}`;

    const details = document.createElement('div');
    details.className = 'session-meta';
    details.textContent = [
      `IP: ${safeText(session.ip) || 'Unknown'}`,
      safeText(session.userAgent) || 'Unknown device',
      session.newDevice ? 'First seen on this device' : session.recognized ? 'Known device' : '',
      session.deviceTrusted ? 'Trusted device' : '',
    ]
      .filter(Boolean)
      .join(' | ');

    li.appendChild(head);
    li.appendChild(meta);
    li.appendChild(details);
    dom.sessionsList.appendChild(li);
  }
};

const renderBackupCodes = (codes = []) => {
  if (!dom.mfaBackupCodes) return;

  dom.mfaBackupCodes.innerHTML = '';
  if (!Array.isArray(codes) || !codes.length) return;

  for (const code of codes) {
    const item = document.createElement('div');
    item.className = 'backup-code-item';
    item.textContent = safeText(code);
    dom.mfaBackupCodes.appendChild(item);
  }
};

const renderMfaState = (user = state.user) => {
  const mfa = normalizeMfaState(user?.security?.mfa);

  if (dom.mfaStatusCopy) {
    if (mfa.enabled) {
      dom.mfaStatusCopy.textContent = `MFA is enabled. Backup codes remaining: ${mfa.backupCodesRemaining}. Last used: ${formatDate(mfa.lastUsedAt)}.`;
    } else if (state.mfaSetup?.secret) {
      dom.mfaStatusCopy.textContent = 'Finish the setup below to enable MFA on your account.';
    } else {
      dom.mfaStatusCopy.textContent = 'MFA is not enabled.';
    }
  }

  if (dom.mfaSetupBtn) dom.mfaSetupBtn.disabled = mfa.enabled;
  if (dom.mfaDisableBtn) dom.mfaDisableBtn.disabled = !mfa.enabled;
  if (dom.mfaBackupBtn) dom.mfaBackupBtn.disabled = !mfa.enabled;
  if (dom.mfaSetupPanel) dom.mfaSetupPanel.hidden = !state.mfaSetup?.secret;
  if (dom.mfaCurrentPassword && !state.mfaSetup?.secret) dom.mfaCurrentPassword.value = '';
  if (dom.mfaSecret) dom.mfaSecret.value = safeText(state.mfaSetup?.secret);
  if (dom.mfaOtpAuthUrl) dom.mfaOtpAuthUrl.value = safeText(state.mfaSetup?.otpAuthUrl);
};

const renderDevices = () => {
  if (!dom.devicesList) return;

  dom.devicesList.innerHTML = '';
  if (!state.devices.length) {
    const li = document.createElement('li');
    li.textContent = 'No known devices found.';
    dom.devicesList.appendChild(li);
    return;
  }

  for (const device of state.devices) {
    const li = document.createElement('li');
    li.className = 'device-card';

    const head = document.createElement('div');
    head.className = 'session-head';

    const title = document.createElement('strong');
    title.textContent = safeText(device.label) || 'Browser device';
    head.appendChild(title);

    const right = document.createElement('div');
    right.className = 'session-actions';

    if (device.current) {
      const currentChip = document.createElement('span');
      currentChip.className = 'inline-chip';
      currentChip.textContent = 'Current device';
      right.appendChild(currentChip);
    }

    const trustBtn = document.createElement('button');
    trustBtn.type = 'button';
    trustBtn.className = 'secondary-btn';
    trustBtn.textContent = device.trusted ? 'Mark Untrusted' : 'Trust Device';
    trustBtn.addEventListener('click', async () => {
      setButtonBusy(trustBtn, true, 'Saving...');
      try {
        await apiRequest(`/devices/${encodeURIComponent(device.fingerprint)}`, {
          method: 'PATCH',
          body: { trusted: !device.trusted },
        });
        await loadDevices();
        await loadCurrentUser();
        showToast(device.trusted ? 'Device marked untrusted.' : 'Device trusted.', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(trustBtn, false);
      }
    });
    right.appendChild(trustBtn);

    const renameBtn = document.createElement('button');
    renameBtn.type = 'button';
    renameBtn.className = 'secondary-btn';
    renameBtn.textContent = 'Rename';
    renameBtn.addEventListener('click', async () => {
      const nextLabel = window.prompt('Device label', safeText(device.label) || 'Browser device');
      if (!nextLabel) return;

      setButtonBusy(renameBtn, true, 'Saving...');
      try {
        await apiRequest(`/devices/${encodeURIComponent(device.fingerprint)}`, {
          method: 'PATCH',
          body: { label: nextLabel },
        });
        await Promise.all([loadDevices(), loadSessions()]);
        showToast('Device label updated.', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(renameBtn, false);
      }
    });
    right.appendChild(renameBtn);

    const forgetBtn = document.createElement('button');
    forgetBtn.type = 'button';
    forgetBtn.className = 'danger-btn';
    forgetBtn.textContent = device.current ? 'Remove Device' : 'Forget Device';
    forgetBtn.addEventListener('click', async () => {
      if (!window.confirm('Remove this device and revoke any sessions tied to it?')) return;

      setButtonBusy(forgetBtn, true, 'Removing...');
      try {
        const data = await apiRequest(`/devices/${encodeURIComponent(device.fingerprint)}`, {
          method: 'DELETE',
          body: { revokeSessions: true },
        });
        showToast(data.message || 'Device removed.', 'success');

        if (data.forceRelogin) {
          clearStoredAuth();
          stopSessionAutoRefresh();
          setLoggedOutUI(true);
          return;
        }

        await Promise.all([loadDevices(), loadSessions(), loadCurrentUser()]);
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(forgetBtn, false);
      }
    });
    right.appendChild(forgetBtn);

    head.appendChild(right);

    const meta = document.createElement('div');
    meta.className = 'session-meta';
    meta.textContent = [
      `Last seen: ${formatDate(device.lastSeenAt)}`,
      `First seen: ${formatDate(device.firstSeenAt)}`,
      device.trusted ? 'Trusted' : 'Untrusted',
      `${Number(device.activeSessions || 0)} active session${Number(device.activeSessions || 0) === 1 ? '' : 's'}`,
    ].join(' | ');

    const detail = document.createElement('div');
    detail.className = 'session-meta';
    detail.textContent = [
      `IP: ${safeText(device.lastIp) || 'Unknown'}`,
      safeText(device.userAgent) || 'Unknown device',
    ]
      .filter(Boolean)
      .join(' | ');

    li.appendChild(head);
    li.appendChild(meta);
    li.appendChild(detail);
    dom.devicesList.appendChild(li);
  }
};

const renderServices = () => {
  if (!dom.serviceList || !dom.serviceCards.length) return;

  const query = safeText(dom.serviceFilter?.value).toLowerCase();
  const sortedCards = [...dom.serviceCards].sort((leftCard, rightCard) => {
    const leftKey = safeText(leftCard.dataset.key).toLowerCase();
    const rightKey = safeText(rightCard.dataset.key).toLowerCase();
    const leftPinned = state.favoriteServices.has(leftKey);
    const rightPinned = state.favoriteServices.has(rightKey);

    if (leftPinned !== rightPinned) {
      return leftPinned ? -1 : 1;
    }

    return safeText(leftCard.dataset.title).localeCompare(safeText(rightCard.dataset.title));
  });

  let visibleCount = 0;

  for (const card of sortedCards) {
    const key = safeText(card.dataset.key).toLowerCase();
    const searchText = [
      card.dataset.title,
      card.dataset.category,
      card.dataset.description,
    ]
      .map((value) => safeText(value).toLowerCase())
      .join(' ');
    const pinned = state.favoriteServices.has(key);
    const matchesQuery = !query || searchText.includes(query);
    const visible = matchesQuery && (!state.favoriteServicesOnly || pinned);

    card.classList.toggle('hidden', !visible);
    card.classList.toggle('pinned', pinned);

    const pinButton = card.querySelector('.service-pin-btn');
    if (pinButton) {
      pinButton.textContent = pinned ? 'Pinned' : 'Pin';
      pinButton.setAttribute('aria-pressed', pinned ? 'true' : 'false');
    }

    dom.serviceList.appendChild(card);

    if (visible) visibleCount += 1;
  }

  if (dom.favoriteFilterBtn) {
    dom.favoriteFilterBtn.classList.toggle('active', state.favoriteServicesOnly);
    dom.favoriteFilterBtn.textContent = state.favoriteServicesOnly ? 'Show all' : 'Pinned only';
  }

  if (dom.serviceResultsCount) {
    const suffix = state.favoriteServicesOnly ? ' pinned view' : ' available';
    dom.serviceResultsCount.textContent = `${visibleCount} service${visibleCount === 1 ? '' : 's'}${suffix}`;
  }

  if (dom.serviceEmptyState) {
    dom.serviceEmptyState.hidden = visibleCount !== 0;
  }
};

const syncUiWithUser = (user) => {
  if (!user) return;

  state.user = user;
  state.activity = Array.isArray(user.recentLogins) ? user.recentLogins : [];
  state.auditEvents = Array.isArray(user.auditEvents) ? user.auditEvents.map((event) => normalizeAuditEvent(event)) : [];
  state.activitySummary = normalizeActivitySummary(user.activitySummary);

  fillSummary(user);
  fillProfile(user);
  fillLinkedAccounts(user);
  fillPreferences(user);
  fillSecurity(user);
  renderActivity();
  renderOverviewActivity();
  renderActivityBars();
  renderInsights();
  renderVerificationState(user);
  renderDevices();
  renderServices();
  renderAvatarPreviews(user);

  const statusText = `Logged in as: ${getUserHandle(user) || user.email || user.displayName || user.userId}`;
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
  state.auditEvents = Array.isArray(data.auditEvents) ? data.auditEvents.map((event) => normalizeAuditEvent(event)) : [];
  state.activitySummary = normalizeActivitySummary(data.summary);

  renderActivity();
  renderOverviewActivity();
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

  updateSessionNote();
};

const loadDevices = async () => {
  const data = await apiRequest('/devices', { method: 'GET', auth: true });
  state.devices = Array.isArray(data.devices) ? data.devices : [];

  if (!state.user) state.user = {};
  if (!state.user.security) state.user.security = {};
  state.user.security.knownDevices = state.devices.length;

  renderDevices();
  updateSessionNote();
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

  if (state.user) {
    fillSummary(state.user);
  }

  renderSessions();

  updateSessionNote();
};

const loadDashboardData = async ({ silent = false } = {}) => {
  if (!silent && dom.loadingMessage) {
    dom.loadingMessage.textContent = 'Loading dashboard...';
  }

  const user = await loadCurrentUser();
  let sessionsError = null;

  try {
    await loadSessions();
  } catch (error) {
    sessionsError = error;
  }

  try {
    await loadDevices();
  } catch (error) {
    if (state.appVisible) {
      showToast('Account loaded, but devices could not be refreshed.', 'warn', 3600);
    }
  }

  if (sessionsError && !state.user) {
    throw sessionsError;
  }

  for (const form of trackedForms) {
    markFormClean(form);
  }
  state.lastSyncAt = new Date();
  setSyncStatus(state.lastSyncAt);

  if (sessionsError && state.appVisible) {
    showToast('Account loaded, but active sessions could not be refreshed.', 'warn', 3600);
  }

  return user;
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
  stripLegacyAuthParamsFromUrl();

  const refreshed = await refreshSession();
  if (!refreshed.ok) return false;

  try {
    await loadDashboardData();
    return true;
  } catch {
    const retry = await refreshSession();
    if (!retry.ok) return false;

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
  stopSessionAutoRefresh();
  setLoggedOutUI(true);
  showToast('Logged out successfully.', 'success');
};

const exportActivityCsv = () => {
  const query = safeText(dom.activityFilter?.value).toLowerCase();
  const kind = safeText(dom.activityKind?.value).toLowerCase() || 'all';
  const items = buildTimelineItems().filter((item) => {
    const matchesKind = kind === 'all' ? true : item.bucket === kind;
    const matchesQuery = !query || item.searchLine.includes(query);
    return matchesKind && matchesQuery;
  });

  if (!items.length) {
    showToast('No activity to export.', 'warn');
    return;
  }

  const header = ['Timestamp', 'Category', 'Title', 'Detail'];
  const rows = items.map((item) => [
    formatDate(item.at),
    item.chip,
    item.title,
    safeText(item.detail).replace(/\n/g, ' '),
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

  const username = safeText(dom.profileUsername?.value).toLowerCase();
  const displayName = safeText(dom.profileDisplayName?.value);
  const pronouns = safeText(dom.profilePronouns?.value);
  const headline = safeText(dom.profileHeadline?.value);
  const email = safeText(dom.profileEmail?.value).toLowerCase();
  const avatar = normalizeAvatarInput(state.profileAvatarDraft || dom.profileAvatarUrl?.value);
  const website = normalizeWebsiteInput(dom.profileWebsite?.value);
  const currentEmail = safeText(state.user?.email).toLowerCase();
  const emailChanged = email !== currentEmail;
  const currentPassword = dom.profileEmailCurrentPassword?.value || '';

  if (!/^[a-z0-9](?:[a-z0-9._-]{1,28}[a-z0-9])?$/.test(username)) {
    showToast('Username must be 3-30 characters and can only use letters, numbers, dots, hyphens, or underscores.', 'error');
    return;
  }

  if (displayName.length < 2) {
    showToast('Display name must be at least 2 characters.', 'error');
    return;
  }

  if ((state.profileAvatarDraft || dom.profileAvatarUrl?.value) && avatar === null) {
    showToast('Avatar must be a direct image URL or an uploaded image.', 'error');
    return;
  }

  if (website === null) {
    showToast('Website URL is invalid.', 'error');
    return;
  }

  if (emailChanged && !currentPassword) {
    showToast('Current password is required to change your email.', 'error');
    return;
  }

  setButtonBusy(dom.profileSaveBtn, true, 'Saving...');

  try {
    const profilePayload = {
      username,
      displayName,
      pronouns,
      headline,
      email,
      currentPassword,
      avatar: avatar || '',
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

    if (dom.profileEmailCurrentPassword) dom.profileEmailCurrentPassword.value = '';
    markFormClean(dom.profileForm);
    showToast(
      profileResult.message || 'Profile updated.',
      profileResult.verificationEmail?.sent === false ? 'warn' : 'success'
    );

    if (profileResult.forceRelogin) {
      clearStoredAuth();
      stopSessionAutoRefresh();
      setTimeout(() => setLoggedOutUI(true), 450);
      return;
    }

    setSyncStatus(new Date());
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.profileSaveBtn, false);
  }
};

const handleResendVerification = async () => {
  if (!state.user || state.user.isVerified) {
    return;
  }

  setButtonBusy(dom.verificationResendBtn, true, 'Sending...');

  try {
    const result = await apiRequest('/resend-verification', {
      method: 'POST',
    });

    syncUiWithUser(normalizeUserPayload(result));
    showToast(
      result.message || 'Verification email sent.',
      result.verificationEmail?.sent ? 'success' : 'warn'
    );
    setSyncStatus(new Date());
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.verificationResendBtn, false);
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
      stopSessionAutoRefresh();
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

const handleMfaSetup = async () => {
  const currentPassword = dom.mfaCurrentPassword?.value || '';
  if (!currentPassword) {
    showToast('Enter your current password to start MFA setup.', 'error');
    return;
  }

  setButtonBusy(dom.mfaSetupBtn, true, 'Preparing...');

  try {
    const data = await apiRequest('/mfa/setup', {
      method: 'POST',
      body: { currentPassword },
    });

    state.mfaSetup = data.setup || null;
    if (dom.mfaCurrentPassword) dom.mfaCurrentPassword.value = '';
    renderBackupCodes(data.setup?.backupCodes || []);
    renderMfaState(state.user);
    showToast('Authenticator setup created.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.mfaSetupBtn, false);
  }
};

const handleMfaEnable = async () => {
  const currentPassword = dom.mfaCurrentPassword?.value || '';
  const code = safeText(dom.mfaCode?.value);
  if (!currentPassword) {
    showToast('Enter your current password to enable MFA.', 'error');
    return;
  }
  if (!code) {
    showToast('Enter the MFA code from your authenticator app.', 'error');
    return;
  }

  setButtonBusy(dom.mfaEnableBtn, true, 'Enabling...');

  try {
    const data = await apiRequest('/mfa/enable', {
      method: 'POST',
      body: { currentPassword, code },
    });

    state.user = normalizeUserPayload(data);
    state.mfaSetup = null;
    if (dom.mfaCurrentPassword) dom.mfaCurrentPassword.value = '';
    if (dom.mfaCode) dom.mfaCode.value = '';
    renderBackupCodes([]);
    syncUiWithUser(state.user);
    showToast('MFA enabled.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.mfaEnableBtn, false);
  }
};

const handleMfaDisable = async () => {
  const currentPassword = window.prompt('Enter your current password to disable MFA.');
  if (!currentPassword) return;

  const code = window.prompt('Enter a current MFA code.');
  if (!code) return;

  setButtonBusy(dom.mfaDisableBtn, true, 'Disabling...');

  try {
    const data = await apiRequest('/mfa/disable', {
      method: 'POST',
      body: { currentPassword, code },
    });

    state.user = normalizeUserPayload(data);
    state.mfaSetup = null;
    renderBackupCodes([]);
    syncUiWithUser(state.user);
    showToast('MFA disabled.', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.mfaDisableBtn, false);
  }
};

const handleMfaBackupCodes = async () => {
  const currentPassword = window.prompt('Enter your current password to regenerate backup codes.');
  if (!currentPassword) return;

  const code = window.prompt('Enter a current MFA code.');
  if (!code) return;

  setButtonBusy(dom.mfaBackupBtn, true, 'Regenerating...');

  try {
    const data = await apiRequest('/mfa/regenerate-backup-codes', {
      method: 'POST',
      body: { currentPassword, code },
    });

    if (!state.user) state.user = {};
    if (!state.user.security) state.user.security = {};
    state.user.security.mfa = normalizeMfaState(data.mfa || state.user.security.mfa);
    renderBackupCodes(data.backupCodes || []);
    renderMfaState(state.user);
    showToast('Backup codes regenerated.', 'success', 4200);
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.mfaBackupBtn, false);
  }
};

const openPublicProfileDirectory = () => {
  const url = new URL('profile.html', window.location.href);
  window.open(url.toString(), '_blank', 'noopener');
};

const buildPreferencesPayload = () => ({
  profilePublic: Boolean(dom.privacyPublic?.checked),
  searchable: Boolean(dom.privacySearchable?.checked),
  publicProfile: {
    headline: Boolean(dom.publicFieldHeadline?.checked),
    bio: Boolean(dom.publicFieldBio?.checked),
    pronouns: Boolean(dom.publicFieldPronouns?.checked),
    location: Boolean(dom.publicFieldLocation?.checked),
    website: Boolean(dom.publicFieldWebsite?.checked),
    timezone: Boolean(dom.publicFieldTimezone?.checked),
    language: Boolean(dom.publicFieldLanguage?.checked),
    linkedAccounts: Boolean(dom.publicFieldLinked?.checked),
    memberSince: Boolean(dom.publicFieldMemberSince?.checked),
  },
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
  renderProfileChecklist(state.user);
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
    stopSessionAutoRefresh();
    setLoggedOutUI(false);
    showToast('Account deleted.', 'success');
    openLoginPopup();
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    setButtonBusy(dom.deleteAccountBtn, false);
  }
};

const syncProfileAvatarDraft = (value) => {
  state.profileAvatarDraft = safeText(value);
  renderAvatarPreviews(state.user);
};

const handleProfileAvatarUrlInput = () => {
  syncProfileAvatarDraft(dom.profileAvatarUrl?.value || '');
};

const handleProfileAvatarUpload = async (event) => {
  const file = event.target?.files?.[0];
  if (!file) return;

  try {
    const avatarDataUrl = await compressAvatarFile(file);
    state.profileAvatarDraft = avatarDataUrl;
    if (dom.profileAvatarUrl) {
      dom.profileAvatarUrl.value = '';
    }
    renderAvatarPreviews(state.user);
    markFormDirty(dom.profileForm);
    showToast('Avatar image ready to save.', 'success');
  } catch (err) {
    if (dom.profileAvatarUpload) {
      dom.profileAvatarUpload.value = '';
    }
    showToast(err.message, 'error');
  }
};

const handleProfileAvatarRemove = () => {
  state.profileAvatarDraft = '';
  if (dom.profileAvatarUrl) {
    dom.profileAvatarUrl.value = '';
  }
  if (dom.profileAvatarUpload) {
    dom.profileAvatarUpload.value = '';
  }
  renderAvatarPreviews(state.user);
  markFormDirty(dom.profileForm);
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
    return;
  }

  switchTab('overview');
};

const setupServiceFiltering = () => {
  if (dom.serviceFilter) {
    dom.serviceFilter.addEventListener('input', () => {
      renderServices();
    });
  }

  if (dom.favoriteFilterBtn) {
    dom.favoriteFilterBtn.addEventListener('click', () => {
      state.favoriteServicesOnly = !state.favoriteServicesOnly;
      persistServicePreferences();
      renderServices();
    });
  }

  for (const card of dom.serviceCards) {
    const pinButton = card.querySelector('.service-pin-btn');
    if (!pinButton) continue;

    pinButton.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();

      const key = safeText(card.dataset.key).toLowerCase();
      if (!key) return;

      if (state.favoriteServices.has(key)) {
        state.favoriteServices.delete(key);
      } else {
        state.favoriteServices.add(key);
      }

      persistServicePreferences();
      renderServices();
    });
  }

  renderServices();
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

  if (dom.overviewJumpProfileBtn) {
    dom.overviewJumpProfileBtn.addEventListener('click', () => {
      switchTab('profile');
      dom.profileUsername?.focus();
    });
  }

  if (dom.overviewJumpSecurityBtn) {
    dom.overviewJumpSecurityBtn.addEventListener('click', () => {
      switchTab('security');
      dom.currentPassword?.focus();
    });
  }

  if (dom.overviewJumpActivityBtn) {
    dom.overviewJumpActivityBtn.addEventListener('click', () => {
      switchTab('activity');
      dom.activityFilter?.focus();
    });
  }

  if (dom.profileAvatarUploadBtn && dom.profileAvatarUpload) {
    dom.profileAvatarUploadBtn.addEventListener('click', () => {
      dom.profileAvatarUpload.click();
    });
    dom.profileAvatarUpload.addEventListener('change', handleProfileAvatarUpload);
  }

  if (dom.profileAvatarUrl) {
    dom.profileAvatarUrl.addEventListener('input', handleProfileAvatarUrlInput);
    dom.profileAvatarUrl.addEventListener('change', handleProfileAvatarUrlInput);
  }

  if (dom.profileAvatarRemoveBtn) {
    dom.profileAvatarRemoveBtn.addEventListener('click', handleProfileAvatarRemove);
  }

  if (dom.profileForm) dom.profileForm.addEventListener('submit', handleProfileSave);
  if (dom.openPublicProfileBtn) {
    dom.openPublicProfileBtn.addEventListener('click', () => {
      const url = getPublicProfileUrl(state.user?.username);
      if (!url || !state.user?.preferences?.profilePublic) return;
      window.open(url, '_blank', 'noopener');
    });
  }
  if (dom.verificationResendBtn) {
    dom.verificationResendBtn.addEventListener('click', handleResendVerification);
  }
  if (dom.linkedForm) dom.linkedForm.addEventListener('submit', handleLinkedSave);
  if (dom.passwordForm) dom.passwordForm.addEventListener('submit', handlePasswordSave);
  if (dom.securityForm) dom.securityForm.addEventListener('submit', handleSecuritySave);
  if (dom.mfaSetupBtn) dom.mfaSetupBtn.addEventListener('click', handleMfaSetup);
  if (dom.mfaEnableBtn) dom.mfaEnableBtn.addEventListener('click', handleMfaEnable);
  if (dom.mfaDisableBtn) dom.mfaDisableBtn.addEventListener('click', handleMfaDisable);
  if (dom.mfaBackupBtn) dom.mfaBackupBtn.addEventListener('click', handleMfaBackupCodes);
  if (dom.publicProfilePreviewBtn) {
    dom.publicProfilePreviewBtn.addEventListener('click', () => {
      const url = getPublicProfileUrl(state.user?.username);
      if (!url) {
        showToast('Set a username before previewing your public profile.', 'error');
        return;
      }
      window.open(url, '_blank', 'noopener');
    });
  }
  if (dom.publicProfileDirectoryBtn) {
    dom.publicProfileDirectoryBtn.addEventListener('click', openPublicProfileDirectory);
  }

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
  if (dom.activityKind) dom.activityKind.addEventListener('change', renderActivity);

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

  if (dom.devicesRefreshBtn) {
    dom.devicesRefreshBtn.addEventListener('click', async () => {
      setButtonBusy(dom.devicesRefreshBtn, true, 'Refreshing...');
      try {
        await loadDevices();
        showToast('Devices refreshed.', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setButtonBusy(dom.devicesRefreshBtn, false);
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
          stopSessionAutoRefresh();
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

    const refreshed = await refreshSession();
    if (!refreshed.ok) {
      showToast('Signed in, but the session could not be established.', 'error');
      return;
    }

    try {
      await loadDashboardData({ silent: true });
      closeLoginPopup();
      showApp();
      startSessionAutoRefresh();
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
  stopSessionAutoRefresh();

  state.refreshTimer = setInterval(async () => {
    const refreshed = await refreshSession();
    if (refreshed.ok) {
      return;
    }

    if (refreshed.reason === 'unauthenticated') {
      handleUnauthenticatedState({
        message: refreshed.message || 'Your session expired. Please sign in again.',
      });
      return;
    }

    if (!navigator.onLine || refreshed.reason === 'network' || refreshed.reason === 'timeout') {
      return;
    }

    if (!state.accessToken) {
      stopSessionAutoRefresh();
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
