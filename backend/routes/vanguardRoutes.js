const express = require('express');
const ctrl = require('../controllers/vanguardController');
const auth = require('../middleware/vanguardAuthMiddleware');

const router = express.Router();

router.get('/health', auth, ctrl.health);
router.post('/license/verify', auth, ctrl.verifyLicense);
router.post('/users/resolve', auth, ctrl.resolveUser);
router.post('/users/flag', auth, ctrl.flagUser);
router.post('/users/unflag', auth, ctrl.unflagUser);

module.exports = router;
