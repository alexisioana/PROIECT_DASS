const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');

const authRoutes = require('./routes/auth');
const passwordRoutes = require('./routes/password');

const app = express();
const PORT = 3000;

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    name: 'sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: 'strict',
        maxAge: 1000 * 60 * 30
    }
}));

app.use('/api/auth', authRoutes);
app.use('/api/password', passwordRoutes);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message);
    if (res.headersSent) return next(err);
    res.status(err.status || 500).json({ error: 'Eroare server' });
});

app.use((req, res) => {
    res.status(404).json({ error: 'Resursa negasita' });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
