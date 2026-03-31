const express = require('express');
const auth = require('../middleware/authMiddleware');
const ctrl = require('../controllers/authController');
const verifyEmailCtrl = require('../controllers/verifyEmailController');

const router = express.Router();

router.post('/register', ctrl.register);
router.post('/login', ctrl.login);
router.post('/logout', ctrl.logout);
router.post('/refresh_token', ctrl.refreshToken);
router.post('/request-password-reset', ctrl.requestPasswordReset);
router.post('/resend-verification-public', ctrl.publicResendVerificationEmail);
router.post('/reset-password', ctrl.resetPassword);
router.get('/verify-email', verifyEmailCtrl.verifyEmail);
router.get('/public-search', ctrl.searchPublicProfiles);
router.get('/public/:username', ctrl.getPublicProfile);

router.get('/me', auth, ctrl.me);
router.post('/resend-verification', auth, ctrl.resendVerificationEmail);
router.patch('/profile', auth, ctrl.updateProfile);
router.patch('/email', auth, ctrl.updateEmail);
router.patch('/password', auth, ctrl.updatePassword);

router.get('/preferences', auth, ctrl.getPreferences);
router.patch('/preferences', auth, ctrl.updatePreferences);

router.get('/linked', auth, ctrl.getLinkedAccounts);
router.patch('/linked', auth, ctrl.updateLinkedAccounts);

router.get('/activity', auth, ctrl.getActivity);

router.get('/security', auth, ctrl.getSecurity);
router.patch('/security', auth, ctrl.updateSecurity);
router.post('/mfa/setup', auth, ctrl.beginMfaSetup);
router.post('/mfa/enable', auth, ctrl.enableMfa);
router.post('/mfa/disable', auth, ctrl.disableMfa);
router.post('/mfa/regenerate-backup-codes', auth, ctrl.regenerateMfaBackupCodes);
router.get('/devices', auth, ctrl.getDevices);
router.patch('/devices/:fingerprint', auth, ctrl.updateDevice);
router.delete('/devices/:fingerprint', auth, ctrl.deleteDevice);
router.get('/sessions', auth, ctrl.getSessions);
router.delete('/sessions/:sessionId', auth, ctrl.revokeSession);
router.delete('/sessions', auth, ctrl.revokeAllSessions);
router.get('/export', auth, ctrl.exportAccountData);

router.delete('/account', auth, ctrl.deleteAccount);

module.exports = router;
