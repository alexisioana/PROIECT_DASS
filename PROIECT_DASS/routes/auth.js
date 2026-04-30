const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../database');

// ============================================
// CONSTANTE SECURITATE
// ============================================
const BCRYPT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;
const PASSWORD_MIN_LENGTH = 8;

// ============================================
// HELPER — validare parola (FIX 4.1)
// ============================================
function validatePassword(password) {
    if (!password || password.length < PASSWORD_MIN_LENGTH) {
        return 'Parola trebuie sa aiba minim 8 caractere';
    }
    if (!/[A-Z]/.test(password)) return 'Parola trebuie sa contina o litera mare';
    if (!/[a-z]/.test(password)) return 'Parola trebuie sa contina o litera mica';
    if (!/[0-9]/.test(password)) return 'Parola trebuie sa contina o cifra';
    if (!/[^A-Za-z0-9]/.test(password)) return 'Parola trebuie sa contina un caracter special';
    return null;
}

// ============================================
// HELPER — log audit
// ============================================
function logAudit(userId, action, ip) {
    try {
        db.prepare(
            'INSERT INTO audit_logs (user_id, action, ip_address) VALUES (?, ?, ?)'
        ).run(userId, action, ip);
    } catch (e) { /* nu blocam fluxul daca log-ul esueaza */ }
}

// ============================================
// REGISTER — v2 SECURIZAT
// ============================================
router.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip;

    if (!email || !password) {
        return res.status(400).json({ error: 'Date invalide' });
    }

    // FIX 4.1: validare parola
    const pwdError = validatePassword(password);
    if (pwdError) {
        return res.status(400).json({ error: pwdError });
    }

    try {
        // FIX 4.2: hash bcrypt cu salt
        const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        const stmt = db.prepare(
            'INSERT INTO users (email, password_hash) VALUES (?, ?)'
        );
        stmt.run(email, hash);

        logAudit(null, 'REGISTER_SUCCESS', ip);

        // FIX 4.4: mesaj generic — nu confirmam succes/duplicat diferit
        res.json({ message: 'Daca emailul este valid, contul a fost creat' });
    } catch (err) {
        // FIX 4.4: NU dezvaluim daca emailul exista deja
        logAudit(null, 'REGISTER_FAIL', ip);
        // FIX 4.7: log intern, raspuns generic
        console.error('[REGISTER]', err.message);
        res.status(400).json({ error: 'Date invalide' });
    }
});

// ============================================
// LOGIN — v2 SECURIZAT
// ============================================
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip;

    if (!email || !password) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }

    try {
        const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

        // FIX 4.3: verificare lockout
        if (user && user.locked_until && new Date(user.locked_until) > new Date()) {
            logAudit(user.id, 'LOGIN_BLOCKED', ip);
            return res.status(429).json({ error: 'Cont blocat temporar. Reincearca mai tarziu.' });
        }

        // FIX 4.4: comparatie cu timp uniform — chiar si pentru user inexistent
        // facem un bcrypt.compare cu un hash "fake" ca sa avem timp de raspuns similar
        const fakeHash = '$2a$12$abcdefghijklmnopqrstuuFakeHashForTimingAttackPrevention';
        const hashToCompare = user ? user.password_hash : fakeHash;
        const valid = await bcrypt.compare(password, hashToCompare);

        if (!user || !valid) {
            // FIX 4.3: incrementare contor failed attempts
            if (user) {
                const attempts = (user.failed_attempts || 0) + 1;
                let lockedUntil = null;
                if (attempts >= MAX_FAILED_ATTEMPTS) {
                    lockedUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000).toISOString();
                }
                db.prepare(
                    'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?'
                ).run(attempts, lockedUntil, user.id);
                logAudit(user.id, 'LOGIN_FAIL', ip);
            }
            // FIX 4.4: mesaj UNIC — fara user enumeration
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Login reusit — resetam contorul
        db.prepare(
            'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?'
        ).run(user.id);

        // FIX 4.5: regenerare ID sesiune (anti session-fixation)
        req.session.regenerate((err) => {
            if (err) {
                console.error('[SESSION]', err.message);
                return res.status(500).json({ error: 'Eroare server' });
            }
            req.session.userId = user.id;
            req.session.email = user.email;
            req.session.role = user.role;

            logAudit(user.id, 'LOGIN_SUCCESS', ip);
            res.json({ message: 'Autentificat cu succes', role: user.role });
        });
    } catch (err) {
        console.error('[LOGIN]', err.message);
        res.status(500).json({ error: 'Eroare server' });
    }
});

// ============================================
// LOGOUT — v2 SECURIZAT
// ============================================
router.post('/logout', (req, res) => {
    const userId = req.session.userId;
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Eroare logout' });
        }
        // FIX 4.5: stergere explicita cookie
        res.clearCookie('connect.sid');
        logAudit(userId, 'LOGOUT', req.ip);
        res.json({ message: 'Deconectat' });
    });
});

// ============================================
// PROFIL
// ============================================
router.get('/profile', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Neautentificat' });
    }
    const user = db.prepare(
        'SELECT id, email, role, created_at FROM users WHERE id = ?'
    ).get(req.session.userId);
    res.json(user);
});

module.exports = router;
