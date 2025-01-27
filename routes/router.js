require('dotenv').config();
const express = require('express');
const router = express.Router();
const User = require('../models/user');
const Product = require('../models/product');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const os = require('os');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require("fs");

// image upload

var storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, './public/uploads');
    },
    filename: function(req, file, cb) {
        cb(null, file.fieldname + "_" + Date.now() + "_" + file.originalname);
    },
});

var upload = multer({
    storage: storage,
}).single('image');  // 'image' is a 'name' field from input tag

// Insert Data in Database

router.use(express.urlencoded({extended: true}));
router.use(express.json());
router.use(cookieParser());
const head_name = process.env.HEAD;
// const secret_key = 'something';

router.post('/register', async (req, res) => {
    try{
        const salt = await bcrypt.genSalt(10);
        const user = new User({
            name: req.body.name,
            email: req.body.email,
            pass: await bcrypt.hash(req.body.pass, salt),
            address: req.body.address,
            phone: req.body.phone,
            role: req.body.role
        });

        await user.save();
        // req.session.message = {};
        res.status(200).send("Successfully Registered... <a href='/'>Click to Login</a>")
    } catch (error) {
        // res.json({});
        console.log(error);
    }
});

router.post('/auth', async (req,res) => {
    try{
        const {email, pass} = req.body; 
        const user = await User.findOne({ email: email }).exec();
        if (!user) {
            return res.status(404).send("User not found... <a href='/'>Back to Login</a>");
        }
        if(await bcrypt.compare(pass, user.pass)) {
            const token = jwt.sign(
                {userId: user._id}, process.env.BYTPASS,
                { expiresIn: process.env.JWTEXP}
            );
            res.cookie('json', token, {
                httpOnly: true,
                secure: false,
                sameSite: 'strict',
                maxAge: process.env.COOEXP * 60 * 60 * 1000,
            });
            res.redirect('/dashboard/home');
        } else {
            res.status(401).send("Invalid Password... <a href='/'>Back to Login</a>");
        }
    } catch (error) {
        console.log(error);
    }
});

router.post("/reset", async (req, res) => {
    const email = req.body.email;
    const user = await User.findOne({ email : email }).exec();
    if(user){
        const encryptedData = encryptLinkData(user._id);
        const link = `${req.protocol}://${req.headers.host}/change?step=${encodeURIComponent(encryptedData)}`;
        // await sendEmail(email, link);
        console.log(`Reset Link: ${link}`);
        res.status(200).send("Link has been sented to the Registered Email. <a href='/'>Click to Login</a>")
    } else {
        return res.status(400).send("No Email has registered... <a href='/'>Back to Login</a>");
    }   
});

router.post("/setpass", async (req, res) => {
    const password = req.body.pass;
    const conf_password = req.body.conf_pass;
    if(password != conf_password){
        return res.send("Password Mismatch... <a href='/'>Back to Login</a>");
    }
    try{
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt)
        const updateUser = await User.findByIdAndUpdate(req.session.user,
            { pass : hashedPassword },
            { new : true }
        );

        if(!updateUser) {
            return res.status(404).send("Session Expired. <a href='/'>Click to Back</a>");
        }

        res.status(200).send("Password updated successfully... <a href='/dashboard/home'>Click to Dashboard</a>");
    } catch(error) {
        console.log(error);
        res.status(404).send("Update Process Failed...");
    }

});

router.post("/update_profile", authToken, async (req, res) => {
    try{
        const updateUser = await User.findByIdAndUpdate(req.auth_user._id,
            { 
                name : req.body.name.trim(),
                email : req.body.email.trim(),
                phone : req.body.phone.trim(),
                address : req.body.address.trim(),
            },
            { new : true }
        );
        if(!updateUser) {
            return res.status(404).send("User not found.");
        }
        res.status(200).send("Profile Updated Successfully... <a href='/dashboard/profile'>Click to Dashboard</a>");

    } catch (error) {
        console.log(error);
        res.send("Updating Profile has been failed due to server error...");
    }
});

router.post('/upload_photo', authToken, upload, async (req, res) => {
    try{
        if(req.file){
            new_image = req.file.filename;
            const updatePhoto = await User.findByIdAndUpdate(req.auth_user._id,
                { photo : new_image },
                { new : true }
            );
            if(!updatePhoto){
                return res.status(401).send("No User found... <a href='/dashboard/home'>Click to Dashboard</a>")
            }
            res.status(200).send("Photo has been Updated... <a href='/dashboard/home'>Click to Dashboard</a>")
            if(req.auth_user.photo){
                try{
                    fs.unlinkSync("./public"+req.body.old_image);
                } catch (error) {
                    console.log(error);
                }
            } 
        }
    } catch(error) {
        console.log(error);
    }
});

// ------------------------------------Product Section ----------------------------------------------------------

router.post('/addproduct', authToken, upload, async (req, res) => {
    try{
        var date = new Date();
        var currentDate = date.getDate()+'-'+(date.getMonth()+1)+'-'+date.getFullYear()+'@'+date.getHours()+':'+date.getMinutes()+':'+date.getSeconds();
        const product = new Product({
            name: req.body.name,
            price: req.body.price,
            quantity: req.body.quantity,
            description: req.body.description,
            seller: req.auth_user._id,
            photo: req.file.filename,
            created: currentDate,
        });
        await product.save();
        res.status(200).send("Product has been Uploaded... <a href='/dashboard/product'>Click here</a>")
    } catch (error) {
        console.log(error);
    }
});

//----------------------------------------------------------------------------------------------------------------

async function getUser(id) {
    try{
        const user = await User.findById(id);
        return user;
    } catch (error) {
        console.log(error);
    }
}

async function sendEmail(recipientEmail, link) {
    try{
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASS,
            },
        });

        const mailOptions = {
            from: '"Smart Agri Connector" <noreply@smartariconnectoru>',
            to: recipientEmail,
            subject: 'Reset Password',
            html: `<p>The Like could be expire in 5 minutes.
            Click the link below to reset your password:</p>
                   <a href="${link}">${link}</a>`,
        };

        const info = await transporter.sendMail(mailOptions);
    } catch (error) {
        console.log('Error sending email: ',error);
    }
}

function getIp(){
    const networkInterfaces = os.networkInterfaces();
    for (const interfaceName in networkInterfaces) {
        for (const interface of networkInterfaces[interfaceName]) {
            if (interface.family === 'IPv4' && !interface.internal) {
                return interface.address;
            }
        }
    }
}

const secretKey = crypto.randomBytes(32).toString("hex").substring(0,32);
const iv = crypto.randomBytes(16);

function encryptLinkData(input){
    const data = JSON.stringify({input, exp: Date.now() + process.env.PASSLINKEXP * 60 * 1000});  //Link Expiry
    const cipher = crypto.createCipheriv("aes-256-cbc", secretKey, iv);
    let encrypted = cipher.update(data, "utf8", "hex");
    encrypted += cipher.final("hex");
    return `${iv.toString("hex")}:${encrypted}`;
}

function decryptLinktData(encryptedData){
    const [ivHex, encrypted] = encryptedData.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", secretKey, iv);
    let decrypted = decipher.update(encrypted, "hex", "utf-8");
    decrypted += decipher.final("utf-8");
    return JSON.parse(decrypted);
}

async function authToken(req, res, next){
    const token = req.cookies.json;
    if(!token) {
        return res.status(401).send('Access denied, Please <a href="/logout">log in</a>...');
    }
    try{
        const decode = jwt.verify(token, process.env.BYTPASS);
        req.auth_user = await getUser(decode.userId);
        next();
    } catch (error) {
        console.log(error);
        res.status(403).send('Invalid or expired token, <a href="/logout">Click to Login</a>');
    }
}

//--------------------------------------------------------------------------------------------------------

router.get("/", (req, res) => {
    if(req.cookies.json){
        return res.redirect('/dashboard/home');
    }
    res.render('index', {head: head_name,title: "Login Page"});
});

router.get("/logout", (req, res) => {
    res.clearCookie('json');
    res.redirect('/');
});

router.get("/register", (req, res) => {
    res.render('register', {head: head_name, title: "Register Page"});
});

router.get("/reset", (req, res) => {
    res.render('reset', {head: head_name, title: "Reset Page"});
});

router.get('/change', (req, res) => {
    try{
        const encryptedData = req.query.step;
        const decryptedData = decryptLinktData(encryptedData);
        if (decryptedData.exp < Date.now()) {
            return res.status(400).send("The Link has Expired... <a href='/'>Click to Login</a>");
        }
        const id = decryptedData.input;
        req.session.user = id;
        req.session.cookie.maxAge = process.env.PASSPAGEEXP * 60 * 1000;
        res.render('password', {head: head_name, title: "Recover Password"});
    } catch(error) {
        console.log(error);
        res.status(400).send("Invalid or Corrupted link...");
    }
});

router.get('/update_password', authToken, (req, res) => {
    try{
        const encryptedData = encryptLinkData(req.auth_user._id);
        res.redirect(`/change?step=${encodeURIComponent(encryptedData)}`);
    } catch (error) {
        console.log(error);
        res.send('Unable to connect.. <a href="/dashboard/home">back to the dashboard</a>');
    }
});

router.get('/dashboard/home', authToken, async (req, res) => {
    const user = req.auth_user;
    res.render('dashboard', {
        title: "Dashboard", user, board: "home"
    });
});

router.get('/dashboard/profile', authToken, (req, res) => {
    const user = req.auth_user;
    res.render('dashboard', {
        title: "Dashboard", user, board: "profile"
    });
});

router.get('/dashboard/photo', authToken, (req, res) => {
    const user = req.auth_user;
    res.render('dashboard', {
        title: "Dasboard", user, board: "photo"
    });
});

router.get('/dashboard/rm-ph', authToken, async (req, res) => {
    try{
        fs.unlinkSync("./public/uploads/"+req.auth_user.photo);
        await User.updateOne(
            {_id : req.auth_user._id},
            { $unset : { photo: ""}}
        );
        res.redirect('/dashboard/home');
    } catch (error) {
        console.log(error);
        res.status(401).send("Failed to Remove Photo.. <a href='/dashboard/home'>Click to Dashboard</a>")
    }
});

//--------------------------------- Product Section ---------------------------------------------

router.get('/dashboard/product', authToken, async (req, res) => {
    const user = req.auth_user;
    const products = await Product.find().exec();
    const result = await User.find({ role: 'farmer' }, { name: 1, phone: 1, address: 1 });
    const farmers = result.reduce((acc, farmer) => {
        acc[farmer._id] = {
          name: farmer.name,
          phone: farmer.phone,
          address: farmer.address,
        };
        return acc;
      }, {});
    res.render('dashboard', {
        title: "Dashboard", user, board: "product", products, farmers
    });
});

router.get('/dashboard/product/add', authToken, (req, res) => {
    const user = req.auth_user;
    res.render('dashboard', {
        title: "Dashboard", user, board: "addProduct"
    });
});

console.log(`Server Started at http://${getIp()}:${process.env.PORT}`);

module.exports = router;