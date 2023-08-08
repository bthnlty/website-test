const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/user_model');

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

            if (_foundUser.password !== password) {
                return done(null, false, { message: 'Şifre/Email yanlış' });
            } else {
                return done(null, _foundUser);
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
                done(null, false); // Kullanıcı bulunamadıysa, false ile işlemi sonlandırın.
            }
        } catch (err) {
            done(err, null);
        }
    });


    /*
        passport.deserializeUser(async function (_id, done) {
            try {
                console.log("Sessiondan alındı");
                const user = await User.findById(_id);
                done(null, user);
            } catch (err) {
                done(err, null);
            }
        });
    */

}