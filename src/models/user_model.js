const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
    name: {
        type: String,
        required: [true, "Adınızı giriniz"],
        trim: true,
        minlength: [2, "Adınız 2 karakterden az olamaz"],
        maxlength: [30, "Adınız 30 karakterden fazla olamaz"]
    },
    surname: {
        type: String,
        required: [true, "Soyadınızı giriniz"],
        trim: true,
        minlength: [2, "Soyadınız 2 karakterden az olamaz"],
        maxlength: [30, "Soyadınız 30 karakterden fazla olamaz"]
    },
    email: {
        type: String,
        required: [true, "Email adresinizi giriniz"],
        trim: true,
        unique: true,
        lowercase: true
    },
    isEmailActive: {
        type: Boolean,
        default: false
    },
    password: {
        type: String,
        required: [true, "Şifrenizi giriniz"],
        trim: true,
    },

}, { collection: 'Users', timestamps: true });

const User = mongoose.model('User', UserSchema);

module.exports = User;