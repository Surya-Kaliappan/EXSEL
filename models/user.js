const mongoose = require('mongoose');
const userScheme = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    pass: {
        type: String,
        required: true,
    },
});

module.exports = mongoose.model("User", userScheme);