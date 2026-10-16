const express = require('express');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const DB_FILE = path.join(__dirname, 'users.json');
let otpStore = {};

function getUsers() {
    if (!fs.existsSync(DB_FILE)) return [];
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveUsers(users) {
    fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// 1. Send OTP API (Using Ethereal Free Test Account / Fallback Mock)
app.post('/api/send-otp', async (req, res) => {
    const { email } = req.body;
    const users = getUsers();
    
    if (users.find(u => u.email === email)) {
        return res.status(400).json({ success: false, message: 'Email already registered!' });
    }

    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    otpStore[email] = otp;

    try {
        // Test account create karne ke liye Ethereal use kar rahe hain (No Password required)
        let testAccount = await nodemailer.createTestAccount();

        let transporter = nodemailer.createTransport({
            host: "smtp.ethereal.email",
            port: 587,
            secure: false,
            auth: {
                user: testAccount.user,
                pass: testAccount.pass,
            },
        });

        let info = await transporter.sendMail({
            from: '"Student Portal" <no-reply@studentportal.com>',
            to: email,
            subject: 'Email Verification OTP',
            text: `Aapka verification OTP code hai: ${otp}`,
            html: `<h3>Aapka verification OTP code hai: <b>${otp}</b></h3>`
        });

        // Console mein preview link print hoga jahan click karke aap OTP dekh sakte hain
        console.log("-----------------------------------------");
        console.log("OTP Email Sent to: " + email);
        console.log("Generated OTP: " + otp);
        console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
        console.log("-----------------------------------------");

        res.json({ 
            success: true, 
            message: 'OTP sent successfully! (Check your terminal/console for the preview link & OTP code).' 
        });

    } catch (error) {
        console.error("Email Error:", error);
        // Fallback: Agar network error ho toh direct response mein OTP bhej do testing ke liye
        res.json({ 
            success: true, 
            message: `Mock OTP Generated: ${otp} (Server fallback)` 
        });
    }
});

app.post('/api/signup', (req, res) => {
    const { name, mobile, email, password, otp } = req.body;

    if (!otpStore[email] || otpStore[email] !== otp) {
        return res.status(400).json({ success: false, message: 'Invalid or expired OTP!' });
    }

    let users = getUsers();
    users.push({ name, mobile, email, password });
    saveUsers(users);

    delete otpStore[email];
    res.json({ success: true, message: 'Account created successfully!' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = getUsers();
    const user = users.find(u => u.email === email && u.password === password);

    if (user) {
        res.json({ success: true, user: { name: user.name, mobile: user.mobile, email: user.email } });
    } else {
        res.status(400).json({ success: false, message: 'Invalid Email ID or Password!' });
    }
});

app.post('/api/reset-password', (req, res) => {
    const { email, newPassword } = req.body;
    let users = getUsers();
    const userIndex = users.findIndex(u => u.email === email);

    if (userIndex === -1) {
        return res.status(400).json({ success: false, message: 'Email not found in database!' });
    }

    users[userIndex].password = newPassword;
    saveUsers(users);
    res.json({ success: true, message: 'Password updated successfully!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
