const { validationResult } = require('express-validator');
const User = require('../models/user_model');
const passport = require('passport');
require('../config/passport_local')(passport);
const bcrypt = require('bcrypt');
const firebase = require('../config/firebase_config');


const showLoginForm = (req, res, next) => {
    res.render('login', {layout: 'layout/auth_layout.ejs'});
}

const login = async (req, res, next) => {
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
  
          // Successfull login
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
          req.flash('error', 'Lütfen e-posta adresinizi doğrulayın');
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
};
  
const showRegisterForm = (req, res, next) => {
    res.render('register', {layout: 'layout/auth_layout.ejs'});
}

const register = async (req, res, next) => {

    const errors = validationResult(req);
    
    if(!errors.isEmpty()) {
        req.flash('validation_error', errors.array());
        req.flash('email', req.body.email);
        req.flash('name', req.body.name);
        req.flash('surname', req.body.surname);
        res.redirect('/register');
    } else {

        try{
            const _user = await User.findOne({email: req.body.email});

            if(_user && _user.isEmailActive == true) {
                req.flash('validation_error', [{msg : 'Bu email adresi ile daha önce kayıt olunmuş'}]);
                req.flash('email', req.body.email);
                req.flash('name', req.body.name);
                req.flash('surname', req.body.surname);
                req.flash('password', req.body.password);
                req.flash('repassword', req.body.repassword)
                res.redirect('/register');
            }else if (_user && _user.isEmailActive == false || _user == null) {
                
                if(_user){
                    await User.findByIdAndRemove({_id : _user._id});
                }
                const newUser = new User({
                    name: req.body.name,
                    surname: req.body.surname,
                    email: req.body.email,
                    password: await bcrypt.hash(req.body.password, 10),
                });
                await newUser.save();
                console.log(newUser);

                
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
                  
                
                  req.flash('success_message', [{msg: 'Lütfen email adresinizi onaylayın'}]);
                  res.redirect('/login');}
        } catch(err) {
            console.log(err);
        }

    }
}

const showForgetPasswordForm = (req, res, next) => {
    res.render('forget_password', {layout: 'layout/auth_layout.ejs'});
}

const forgetPassword = (req, res, next) => {
    console.log(req.body);
    res.render('forget_password', {layout: 'layout/auth_layout.ejs'});
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

module.exports = {
    showLoginForm,
    showRegisterForm,
    showForgetPasswordForm,
    register,
    login,
    forgetPassword,
    logout
}