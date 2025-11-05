const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 5000;
const SECRET_KEY = 'srinivaskeystackgarud';

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('users.db');
db.serialize(() => {
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

app.get('/', (req, res) => {
    res.send('Server is running');
});

app.post('/api/signup', async (req, res) => {
    const { first_name, last_name, email, password } = req.body;
    if (!first_name || !last_name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            `INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)`,
            [first_name, last_name, email, hashedPassword],
            function (err) {
                if (err) {
                    return res.status(500).json({ message: 'Error registering user', error: err.message });
                }
                res.status(201).json({ message: 'User registered successfully' });
            }
        );
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Sign-In Route
app.post('/api/signin', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ message: 'Database error', error: err.message });
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        try {
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
            res.status(200).json({ message: 'Login successful', token });
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    });
});

app.get('/dashboard', authenticateToken, (req, res) => {
    res.status(200).json({
        message: 'Welcome to the Dashboard',
        user: req.user
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

