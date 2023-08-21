const router = require('express').Router();
const authController = require('../controllers/auth_controller');
const validatorMiddleware = require('../middlewares/validation_middleware');
const authMiddleware = require('../middlewares/auth_middleware');

router.get('/login', authMiddleware.unactiveUser, authController.showLoginForm);
router.post('/login', authMiddleware.unactiveUser, validatorMiddleware.validateLogin(), authController.login);

router.get('/register', authMiddleware.unactiveUser, authController.showRegisterForm);
router.post('/register', authMiddleware.unactiveUser, validatorMiddleware.validateNewUser(), authController.register);

router.get('/forget-password', authMiddleware.unactiveUser, authController.showForgetPasswordForm);
router.post('/forget-password', authMiddleware.unactiveUser, validatorMiddleware.validateEmail(), authController.forgetPassword);

router.get('/verify', authController.verifyMail);

router.get('/reset-password/:id/:token', authController.newPasswordForm);
router.get('/reset-password', authController.newPasswordForm);

router.get('/logout', authMiddleware.activeUser, authController.logout);

module.exports = router;