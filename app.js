const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');



// template engine settings
const ejs = require('ejs');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
app.use(expressLayouts);
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.resolve(__dirname, './src/views'));


const sayac = 0;

// db connection
require('./src/config/database');
const MongoDBStore = require('connect-mongodb-session')(session);

const sessionStore = new MongoDBStore({
    uri: process.env.MONGODB_CONNECTION_STRING,
    collection: 'sessions'
});



// session & flash messages
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24,
    },
    store: sessionStore
}));

app.use(flash());
app.use((req, res, next) => {
    res.locals.validation_error = req.flash('validation_error');
    res.locals.success_message = req.flash('success_message');
    res.locals.email = req.flash('email');
    res.locals.name = req.flash('name')
    res.locals.surname = req.flash('surname');
    res.locals.password = req.flash('password');
    res.locals.repassword = req.flash('repassword');


    res.locals.login_error = req.flash('error');

    next();
});

app.use(passport.initialize());
app.use(passport.session());

// routes import
const authRouter = require('./src/routers/auth_router');
const adminRouter = require('./src/routers/admin_router');

// middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// routes
app.get('/', (req, res) => {
    if (req.session.sayac) {
        req.session.sayac++;
    } else {
        req.session.sayac = 1;
    }
    res.json({ message: 'Hello', sayac: req.session.sayac, user: req.user });
});

app.use('/', authRouter);
app.use('/admin', adminRouter);

// server
app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});