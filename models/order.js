const mongoose = require('mongoose');
const orderScheme = new mongoose.Schema({
    product: {
        type: mongoose.Types.ObjectId,
        required: true,
    },
    seller: {
        type: mongoose.Types.ObjectId,
        required: true,
    },
    buyer: {
        type: mongoose.Types.ObjectId,
        required: true,
    },
    quantity: {
        type: String,
        required: true,
    },
    status: {
        type: String,
        required: true,
        default: "0"
    },
    requested: {
        type: String,
        required: true,
    }
});

module.exports = mongoose.model("Order", orderScheme);