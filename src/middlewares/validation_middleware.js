const { body } = require('express-validator');


const validateNewUser = () => {
    return [
        body('email').trim()
            .isEmail().withMessage('Geçerli bir email adresi giriniz.'),
        body('password').trim()
            .isLength({ min: 6 }).withMessage('Şifreniz en az 6 karakterden oluşmalıdır.')
            .isLength({ max: 20 }).withMessage('Şifreniz en fazla 20 karakterden oluşmalıdır.'),
        body('name').trim()
            .isLength({ min: 2 }).withMessage('İsminiz en az 2 karakterden oluşmalıdır.')
            .isLength({ max: 20 }).withMessage('İsminiz en fazla 20 karakterden oluşmalıdır.'),
        body('surname').trim()
            .isLength({ min: 2 }).withMessage('Soyisminiz en az 2 karakterden oluşmalıdır.')
            .isLength({ max: 20 }).withMessage('Soyisminiz en fazla 20 karakterden oluşmalıdır.'),
        body('repassword').trim()
            .custom((value, { req }) => {
                if (value !== req.body.password) {
                    throw new Error('Şifreleriniz eşleşmiyor.');
                }
                return true;
            })
    ];
}


const validateLogin = () => {
    return [
        body('email').trim()
            .isEmail().withMessage('Geçerli bir email adresi giriniz.'),
        body('password').trim()
            .isLength({ min: 6 }).withMessage('Şifreniz en az 6 karakterden oluşmalıdır.')
            .isLength({ max: 20 }).withMessage('Şifreniz en fazla 20 karakterden oluşmalıdır.'),
    ];
}

const validateEmail = () => {
    return [
        body('email').trim()
            .isEmail().withMessage('Geçerli bir email adresi giriniz.')
    ];
}

module.exports = {
    validateNewUser,
    validateLogin,
    validateEmail
}