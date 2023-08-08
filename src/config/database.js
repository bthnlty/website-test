const mongoose = require('mongoose');

mongoose.connect(process.env.MONGODB_CONNECTION_STRING, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    })
    .then(() => console.log('Database connected'))
    .catch(err => console.log("Database connection error: ", err));