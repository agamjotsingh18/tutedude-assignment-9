const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');
const User = require('./models/User');

const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());

mongoose.connect('mongodb://localhost:27017/secretsApp');

// Secret key for JWT
const JWT_SECRET = 'your-strong-secret-key';

// Home redirects to login
app.get('/', (req, res) => res.redirect('/login'));

// Render Register
app.get('/register', (req, res) => res.render('register', { errors: [] }));

// Register POST
app.post('/register',
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,8}$/).withMessage('Password must include lowercase, uppercase, number, and 6-8 chars'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render('register', { errors: errors.array() });
        }

        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        await User.create({ name, email, password: hashedPassword });
        res.redirect('/login');
    }
);

// Render Login
app.get('/login', (req, res) => res.render('login', { errors: [] }));

// Login POST
app.post('/login',
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').notEmpty().withMessage('Password required'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render('login', { errors: errors.array() });
        }

        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.render('login', { errors: [{ msg: 'Invalid email or password' }] });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true, secure: false }); // set `secure: true` in production with HTTPS
        res.redirect('/secrets');
    }
);

// Protected Secrets Page
app.get('/secrets', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        res.render('secrets', { user });
    } catch (err) {
        res.clearCookie('token');
        res.redirect('/login');
    }
});

// Logout
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
