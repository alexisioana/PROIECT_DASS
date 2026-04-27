const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');

const authRoutes = require('./routes/auth');
const passwordRoutes = require('./routes/password');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Sesiune (v1 — intentionat nesigura)
app.use(session({
    secret: 'secret123',        // v1: secret slab
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: false,          // v1: vulnerabil XSS
        secure: false,
        maxAge: 1000 * 60 * 60 * 24 * 30  // v1: 30 zile — prea lung
    }
}));

// Rute
app.use('/api/auth', authRoutes);
app.use('/api/password', passwordRoutes);

// Pagina principala
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});