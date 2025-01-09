require('dotenv').config();
const express = require('express');
const router = express.Router();
const User = require('../models/user');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const os = require('os');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

// image upload

// var storage = multer.diskStorage({
//     destination: function(req, file, cb) {
//         cb(null, './uploads');
//     },
//     filename: function(req, file, cb) {
//         cb(null, file.fieldname + "_" + Date.now() + "_" + file.originalname);
//     },
// });

// var upload = multer({
//     storage: storage,
// }).single('image');  // 'image' is a 'name' field from input tag

// Insert Data in Database

router.use(express.urlencoded({extended: true}));
router.use(express.json());
router.use(cookieParser());
const head_name = process.env.HEAD;
const secret_key = 'something';

router.post('/register', async (req, res) => {
    try{
        const salt = await bcrypt.genSalt(10);
        const user = new User({
            name: req.body.name,
            email: req.body.email,
            pass: await bcrypt.hash(req.body.pass, salt),
        });

        await user.save();
        // req.session.message = {};
        console.log("Successfully Registered...");
        res.redirect('/');
    } catch (error) {
        // res.json({});
        console.log(error.message);
    }
});

router.post('/auth', async (req,res) => {
    try{
        const {email, pass} = req.body; 
        const user = await User.findOne({ email }).exec();
        if (!user) {
            return res.status(404).send("User not found...");
        }
        if(await bcrypt.compare(pass, user.pass)) {
            // res.status(200).send("Login Successful...");
            const token = jwt.sign(
                { userId : user._id }, secret_key,
                { expiresIn: '1m'}
            );
            res.cookie('json', token, {
                httpOnly: true,
                secure: false,
                sameSite: 'strict',
                maxAge: 60*1000,
            });
            res.redirect('/dashboard');
        } else {
            res.status(401).send("Incorrect password...");
        }
    } catch (error) {
        console.log(error.message);
    }
});

router.post("/reset", async (req, res) => {
    const email = req.body.email;
    const user = await User.findOne({ email : email }).exec();
    if(user){
        const encryptedData = encryptLinkData(user._id);
        const link = `http://${getIp()}:${process.env.PORT}/change?step=${encodeURIComponent(encryptedData)}`;
        await sendEmail(email, link);
        console.log(`Reset Link: ${link}`);
        res.redirect('/');
    } else {
        return res.status(400).send("No Email has registered...");
    }   
});

router.post("/setpass", async (req, res) => {

    const password = req.body.pass;
    const conf_password = req.body.conf_pass;
    if(password != conf_password){
        return res.send("Password Mismatch...");
    }
    try{
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt)
        const updateUser = await User.findByIdAndUpdate(req.session.user,
            { pass : hashedPassword},
            { new : true}
        );

        if(!updateUser) {
            return res.status(404).send("User not found.");
        }

        res.status(200).send("Password updated successfully...");
    } catch(error) {
        console.log(error);
        res.status(404).send("Update Process Failed...");
    }

});

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
            html: `<p>Click the link below to reset your password:</p>
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
    const data = JSON.stringify({input, exp: Date.now() + 1 * 60 * 1000});  //Link Expiry
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

function authToken(req, res, next){
    const token = req.cookies.json;
    console.log(token);
    if(!token) {
        return res.status(401).send('Access denied, Please log in...');
    }
    try{
        const decode = jwt.verify(token, secret_key);
        req.auth_user = decode;
        next();
    } catch (error) {
        res.status(403).send('Invalid or expired token');
    }
}

router.get("/", (req, res) => {
    if(req.cookies.json){
        return res.redirect('/dashboard');
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
    const encryptedData = req.query.step;
    try{
        const decryptedData = decryptLinktData(encryptedData);
        if (decryptedData.exp < Date.now()) {
            return res.status(400).send("The Link has Expired...");
        }
        const id = decryptedData.input;
        req.session.user = id;
        req.session.cookie.maxAge = 1 * 60 * 1000;
        res.render('password', {head: head_name, title: "Recover Password"});
    } catch(error) {
        console.log(error);
        res.status(400).send("Invalid or Corrupted link...");
    }
});

router.get('/dashboard', authToken, (req, res) => {
    res.render('dashboard', {title: "Dashboard"});
});

console.log(`Server Started at http://${getIp()}:${process.env.PORT}`);

module.exports = router;