const { validationResult } = require('express-validator');
const User = require('../models/user_model');
const passport = require('passport');
require('../config/passport_local')(passport);
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const firebase = require('../config/firebase_config');


const showLoginForm = (req, res, next) => {
  res.render('login', { layout: 'layout/auth_layout.ejs' });
}

const login = async (req, res, next) => {
  const errors = validationResult(req);
  req.flash('email', req.body.email);
  req.flash('password', req.body.password);
  if (!errors.isEmpty()) {
    req.flash('validation_error', errors.array());

    res.redirect('/login');
  } else {

    passport.authenticate('local', {
      successRedirect: '/admin',
      failureRedirect: '/login',
      failureFlash: true
    })(req, res, next);
  }

};

const showRegisterForm = (req, res, next) => {
  res.render('register', { layout: 'layout/auth_layout.ejs' });
}

const register = async (req, res, next) => {

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    req.flash('validation_error', errors.array());
    req.flash('email', req.body.email);
    req.flash('name', req.body.name);
    req.flash('surname', req.body.surname);
    res.redirect('/register');
  } else {

    try {
      const _user = await User.findOne({ email: req.body.email });

      if (_user && _user.isEmailActive == true) {
        req.flash('validation_error', [{ msg: 'Bu email adresi ile daha önce kayıt olunmuş' }]);
        req.flash('email', req.body.email);
        req.flash('name', req.body.name);
        req.flash('surname', req.body.surname);
        req.flash('password', req.body.password);
        req.flash('repassword', req.body.repassword)
        res.redirect('/register');
      } else if ((_user && _user.isEmailActive == false) || _user == null) {

        if (_user) {
          await User.findByIdAndRemove({ _id: _user._id });
        }
        const newUser = new User({
          name: req.body.name,
          surname: req.body.surname,
          email: req.body.email,
          password: await bcrypt.hash(req.body.password, 10),
        });
        await newUser.save();
        console.log(newUser);

        const jwtInfo = {
          id: newUser._id,
          email: newUser.email
        }
        const secret = `${process.env.JWT_SECRET}`;
        const jwtToken = jwt.sign(jwtInfo, secret, { expiresIn: '1h' });
        const url = `${process.env.WEB_SITE_URL}verify?id=${jwtToken}`;

        let transporter = nodemailer.createTransport({

          host: process.env.SMTP_HOST,
          port: process.env.SMTP_PORT,
          secure: true,
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
          }
        });

        await transporter.sendMail({
          from: 'Test Uygulaması <info@denedimbecerdim.com>',
          to: newUser.email,
          subject: 'Email Onay',
          html: "Mailinizi onaylamak için <br> <a href='" + url + "'>" + url + "</a>"
        }, (error, info) => {
          if (error) {
            console.log(error);
          } else {
            console.log("Mail gönderildi");
            console.log(info)
          }
          transporter.close();
        })


        req.flash('success_message', [{ msg: 'Lütfen email adresinizi onaylayın' }]);
        res.redirect('/login');
      }
    } catch (err) {
      console.log(err);
    }

  }
}

const showForgetPasswordForm = (req, res, next) => {
  res.render('forget_password', { layout: 'layout/auth_layout.ejs' });
}

const forgetPassword = async (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    req.flash('validation_error', errors.array());
    req.flash('email', req.body.email);
    res.redirect('/forget-password');
  } else {

    try {
      const _user = await User.findOne({ email: req.body.email, isEmailActive: true });

      if (_user) {
        const jwtInfo = {
          email: _user.email,
          id: _user._id
        }
        const secret = process.env.RESET_PASSWORD_JWT_SECRET + '-' + _user.password;
        const jwtToken = jwt.sign(jwtInfo, secret, { expiresIn: '1h' });

        const url = process.env.WEB_SITE_URL + `reset-password/${_user._id}/` + jwtToken;
        console.log(url);

        let transporter = nodemailer.createTransport({

          host: process.env.SMTP_HOST,
          port: process.env.SMTP_PORT,
          secure: true,
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
          }
        });

        await transporter.sendMail({
          from: 'Test Uygulaması <info@denedimbecerdim.com>',
          to: _user.email,
          subject: "Şifre Sıfırlama",
          html: "Şifrenizi sıfırlamak için lütfen aşağıdaki linke tıklayın <br> <a href='" + url + "'>" + url + "</a>"
        }, (error, info) => {
          if (error) {
            console.log(error);
          } else {
            console.log('Email gönderildi');
            console.log(info);
          }
          transporter.close();
        });

        req.flash('success_message', [{ msg: 'Şifre sıfırlama linki email adresinize gönderildi' }]);
        res.redirect('/login');

      } else {
        req.flash('validation_error', [{ msg: 'Bu email adresi kayıtlı değil veya pasif' }]);
        req.flash('email', req.body.email);
        res.redirect('/forget-password');
      }
    } catch (error) {
      console.log(error);
    }
  }

}

const logout = (req, res, next) => {
  req.logout((error) => {
    if (error) {
      console.error('Oturum kapatılırken bir hata oluştu', error);
      return next(error);
    }
    req.session.destroy((error) => {
      if (error) {
        console.error('Logout error:', error);
        return res.status(500).json({ error: 'Server error' });
      }
      res.clearCookie('connect.sid');
      res.render('login', { layout: 'layout/auth_layout.ejs', success_message: [{ msg: 'Başarıyla çıkış yaptınız' }] });
    });
  });
};

const verifyMail = (req, res, next) => {
  const token = req.query.id;
  if (token) {
    try {
      jwt.verify(token, process.env.JWT_SECRET, async (error, decoded) => {
        if (error) {
          req.flash('error', ' Kod Hatalı veya Süresi Geçmiş')
          res.redirect('/login')
        } else {
          const valueIdInToken = decoded.id;
          const result = await User.findByIdAndUpdate(valueIdInToken, { isEmailActive: true });

          if (result) {
            req.flash('success_message', [{ msg: 'Mail Başarıyla Onaylandı' }]);
            res.redirect('/login')
          } else {
            req.flash('error', 'Geçersiz Link Adresi');
            res.redirect('/login')
          }
        }
      })
    } catch (error) {
      console.log(error);
    }
  } else {
    req.flash('error', 'Geçersiz Link Adresi');
    res.redirect('/login')
  }
}

const newPasswordForm = async (req, res, next) => {
  const linksId = req.params.id;
  const linksToken = req.params.token;

  if (linksId && linksToken) {

    const _findUser = await User.findOne({ _id: linksId });

    const secret = process.env.RESET_PASSWORD_JWT_SECRET + '-' + _findUser.password;

    try {
      jwt.verify(linksToken, secret, async (error, decoded) => {
        if (error) {
          req.flash('error', ' Kod Hatalı veya Süresi Geçmiş')
          res.redirect('/login')
        } else {

          

          /*
          const valueIdInToken = decoded.id;
          const result = await User.findByIdAndUpdate(valueIdInToken, { isEmailActive: true });

          if (result) {
            req.flash('success_message', [{ msg: 'Mail Başarıyla Onaylandı' }]);
            res.redirect('/login')
          } else {
            req.flash('error', 'Geçersiz Link Adresi');
            res.redirect('/login')
          }
          */
        }
      })
    } catch (error) {
      console.log(error);
    }
  } else {
    req.flash('error', 'Geçersiz Link Adresi');
    res.redirect('/login')
  }
}

module.exports = {
  showLoginForm,
  showRegisterForm,
  showForgetPasswordForm,
  register,
  login,
  forgetPassword,
  logout,
  verifyMail,
  newPasswordForm
}


/*
try {
          // User added to database, send verification email
          const userCredential = await firebase.auth().createUserWithEmailAndPassword(newUser.email, "123456");
          const user = userCredential.user;

          // User is created, send verification email
          await user.sendEmailVerification();
          console.log('Email gönderildi');

        } catch (error) {
          console.log('Kullanıcı kaydı veya email gönderme hatası', error);
        }


        */

/*
const errors = validationResult(req);
req.flash('email', req.body.email);
req.flash('password', req.body.password);

if (!errors.isEmpty()) {
req.flash('validation_error', errors.array());
res.redirect('/login');
} else {
try {
const email = req.body.email;
const password = req.body.password;

// Firebase controls
await firebase.auth().signInWithEmailAndPassword(email, "123456");

// User is signed in
const currentUser = firebase.auth().currentUser;
if (currentUser.emailVerified) {
// If user is verified, find user

// Password is correct, find user
const user = await User.findOne({ email: currentUser.email });
if (!user) {
  // User not found
  throw new Error('Kullanıcı bulunamadı');
}

const isPasswordMatch = await bcrypt.compare(password, user.password);
if (!isPasswordMatch) {
  // Password is not correct
  throw new Error('Geçersiz parola');
}

// If user is not active, activate it
await User.findOneAndUpdate({ email: currentUser.email }, { isEmailActive: true });

// Successful login
req.login(user, (error) => {
  if (error) {
    console.error('Oturum açma hatası', error);
    req.flash('error', 'Oturum açarken bir hata oluştu');
    res.redirect('/login');
  } else {
    res.redirect('/admin');
  }
});
} else {
// E-mail address is not verified 
req.flash('error', 'Lütfen E-mail adresinizi doğrulayın');
res.redirect('/login');
return;
}
} catch (error) {
// Login error
console.error(error);
req.flash('error', 'Giriş yapılırken bir hata oluştu');
res.redirect('/login');
}
}
*/