const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const passwordRoutes = require('./routes/password');

const app = express();
const PORT = 3000;

// FIX 4.5: secret puternic (in productie -> variabila de mediu)
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

// FIX bonus: rate limiter global - 100 req/15 min/IP
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Prea multe cereri. Reincearca mai tarziu.' }
});

// FIX bonus: rate limiter strict pentru autentificare - 10 req/15 min/IP
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: { error: 'Prea multe incercari de autentificare. Reincearca peste 15 minute.' }
});

// Middleware
app.use(express.json({ limit: '10kb' })); // FIX bonus: limit body
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// FIX 4.5: sesiune SECURIZATA
app.use(session({
    name: 'sid',                       // FIX: nume custom (ascundem stack-ul)
    secret: SESSION_SECRET,            // FIX: secret puternic random
    resave: false,
    saveUninitialized: false,
    rolling: true,                     // resetare TTL la fiecare request
    cookie: {
        httpOnly: true,                // FIX 4.5: nu poate fi citit din JS (anti-XSS)
        secure: false,                 // pune TRUE in productie cu HTTPS
        sameSite: 'strict',            // FIX 4.5: anti-CSRF
        maxAge: 1000 * 60 * 30         // FIX 4.5: 30 min (era 30 zile)
    }
}));

// FIX bonus: aplicam rate limiter global
app.use(globalLimiter);

// Rute - cu rate limiter strict pe rutele de auth
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/password', authLimiter, passwordRoutes);

// Pagina principala
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// FIX 4.7 (bonus): error handler global - fara stack trace la client
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message); // log intern
    if (res.headersSent) return next(err);
    // Mesaj generic catre client
    res.status(err.status || 500).json({ error: 'Eroare server' });
});

// FIX 4.7: 404 generic
app.use((req, res) => {
    res.status(404).json({ error: 'Resursa negasita' });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});