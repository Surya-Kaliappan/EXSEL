const mongoose = require("mongoose");
const {Schema} = mongoose;

const adminSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  orders: [
    {
      type: Schema.Types.ObjectId,
      ref: "products",
    },
  ],
  products: [
    {
      type: Schema.Types.ObjectId,
      ref: "products",
    },
  ],
  users: [
    {
      type: Schema.Types.ObjectId,
      ref: "User",
    },
  ],
  farmers: [
    {
      type: Schema.Types.ObjectId,
      ref: "User",
    },
  ],
  role: {
    type: String,
    default: "admin",
  },
  photo: {
    type: String,
  },
  phone: {
    type: String,
    required: true,
  },
});

module.exports = mongoose.model("Admin", adminSchema);
