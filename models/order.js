const mongoose = require('mongoose');
const orderScheme = new mongoose.Schema({
    product: {
        type: String,
        required: true,
    },
    seller: {
        type: String,
        required: true,
    },
    buyer: {
        type: String,
        required: true,
    },
    quantity: {
        type: String,
        required: true,
    },
    created: {
        type: String,
        required: true,
    }
});

module.exports = mongoose.model("Orders", orderScheme);