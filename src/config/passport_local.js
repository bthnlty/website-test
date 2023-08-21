const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/user_model');
const bcrypt = require('bcrypt');

module.exports = (passport) => {
    const options = {
        usernameField: 'email',
        passwordField: 'password',
    };
    passport.use(new LocalStrategy(options, async (email, password, done) => {

        try {
            const _foundUser = await User.findOne({ email: email });
            if (!_foundUser) {
                return done(null, false, { message: 'Şifre/Email yanlış' });
            }
            const isMatch = await bcrypt.compare(password, _foundUser.password);
            if (!isMatch) {
                return done(null, false, { message: 'Şifre/Email yanlış' });
            } else {
                if (_foundUser && _foundUser.isEmailActive == false) {
                    return done(null, false, { message: 'Lütfen Giriş Yapmak İçin Mailinizi Onaylayın' })
                } else {
                    return done(null, _foundUser);
                }
            }
        } catch (err) {
            return done(err);
        }


    }));

    passport.serializeUser(function (user, done) {
        console.log("Sessiona kaydedildi" + user._id);
        done(null, user._id);
    });

    passport.deserializeUser(async function (_id, done) {
        try {
            const user = await User.findById(_id);
            if (user) {
                const newUser = {
                    Email: user.email,
                    Ad: user.name,
                    Soyad: user.surname,
                };
                done(null, newUser);
            } else {
                done(null, false);
            }
        } catch (err) {
            done(err, null);
        }
    });

}