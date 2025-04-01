const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const Admin = require("../models/admin");
const User = require("../models/user");
const product = require("../models/product");
const order = require("../models/order");

router.post("/register", async (req, res) => {
  try {
    console.log("Request Body:", req.body);
    if (!req.body.password) {
      return res.status(400).json({ error: "Password is required" });
    }
    const existingAdmin = await Admin.findOne({ role: "admin" });
    if (existingAdmin) {
      console.log("Unauthorized access - Admin already exists");
      return res.status(403).json({ error: "Admin already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    const user = new Admin({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
      phone: req.body.phone,
      role: "admin",
    });

    await user.save();

    console.log("Successfully created admin account");
    return res.redirect("/");
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

router.get("/dashboard", async (req, res) => {
  return res.render("adminDash",{feature: "dashboard"});
});

router.get("/allUsers", async (req, res) => {
  try {
    const admin = await Admin.findOne();
    const usersId = admin.users;
    const users = await User.find({ _id: { $in: usersId } });
    console.log(users);
    return res.render("allUsers",{users});
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.get("/deleteUser/:id", async (req, res) => {
  try {
      await User.findByIdAndDelete(req.params.id);
      res.redirect("/admin/dashboard");
  } catch (error) {
      console.error(error);
      res.status(500).send("Error deleting user.");
  }
});

router.get("/loadContent", async (req, res) => {
  const feature = req.query.feature;

  try {
      if (feature === "dashboard") {
          res.send("<h2>Welcome to Admin Dashboard</h2>");
      } else if (feature === "users") {
          const admin = await Admin.findOne();
          const usersId = admin.users;
          const users = await User.find({ _id: { $in: usersId } });
          res.render("admin/allUsers", { users });
      } else if (feature === "farmers") {
        const admin = await Admin.findOne();
        const farmersId = admin.farmers;
        const farmers = await User.find({_id: { $in: farmersId }});
        res.render("admin/Allfarmers",{farmers});
      } else if (feature === "products") {
        const products = await product.find();
        res.render("admin/Allproduct",{products});
      } else if (feature === "orders") {
        const orders = await order.find();
          res.render("admin/AllOrders",{orders});
      } else {
          res.send("<p class='text-danger'>Invalid Feature Selected</p>");
      }
  } catch (error) {
      console.error(error);
      res.status(500).send("<p class='text-danger'>Error loading content.</p>");
  }
});



module.exports = router;
