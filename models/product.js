const mongoose = require('mongoose');
const productScheme = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    price: {
        type: String,
        required: true,
    },
    quantity: {
        type: String,
        required: true,
    },
    description: {
        type: String,
        required: true,
    },
    seller: {
        type: String,
        required: true,
    },
    photo: {
        type: String,
        required: true,
    },
    created: {
        type: String,
        required: true,
    }
});

module.exports = mongoose.model("Product", productScheme);