const express = require('express');
const auth = require('../middleware/authMiddleware');
const ctrl = require('../controllers/authController');
const verifyEmailCtrl = require('../controllers/verifyEmailController');

const router = express.Router();

router.post('/register', ctrl.register);
router.post('/login', ctrl.login);
router.post('/logout', ctrl.logout);
router.post('/refresh_token', ctrl.refreshToken);
router.get('/verify-email', verifyEmailCtrl.verifyEmail);

router.get('/me', auth, ctrl.me);
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

router.delete('/account', auth, ctrl.deleteAccount);

module.exports = router;
