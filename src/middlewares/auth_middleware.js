const activeUser = (req, res, next) => {
    if(req.isAuthenticated()) {
        next();
    } else {
        req.flash('error', ['Lütfen giriş yapınız'])
        res.redirect('/login');
    }
}

const unactiveUser = (req, res, next) => {
    if(!req.isAuthenticated()) {
        next();
    } else {
        res.redirect('/admin');
    }
}

module.exports = {
    activeUser,
    unactiveUser
}