const express = require('express');
const router = express.Router();
const auth = require('../middleware/authMiddleware');
const ctrl = require('../controllers/authController');

router.post('/register', ctrl.register);
router.post('/login', ctrl.login);
router.post('/logout', ctrl.logout);
router.get('/me', auth, ctrl.me);
router.post('/refresh_token', ctrl.refreshToken);
router.patch('/email', auth, ctrl.updateEmail);
router.patch('/password', auth, ctrl.updatePassword);
router.delete('/account', auth, ctrl.deleteAccount);

module.exports = router;
