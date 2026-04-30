const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../database');

const BCRYPT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;
const PASSWORD_MIN_LENGTH = 8;

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

function logAudit(userId, action, ip) {
    try {
        db.prepare(
            'INSERT INTO audit_logs (user_id, action, ip_address) VALUES (?, ?, ?)'
        ).run(userId, action, ip);
    } catch (e) {}
}

router.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip;

    if (!email || !password) {
        return res.status(400).json({ error: 'Date invalide' });
    }

    const pwdError = validatePassword(password);
    if (pwdError) {
        return res.status(400).json({ error: pwdError });
    }

    try {
        const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

        const stmt = db.prepare(
            'INSERT INTO users (email, password_hash) VALUES (?, ?)'
        );
        stmt.run(email, hash);

        logAudit(null, 'REGISTER_SUCCESS', ip);

        res.json({ message: 'Daca emailul este valid, contul a fost creat' });
    } catch (err) {
        logAudit(null, 'REGISTER_FAIL', ip);
        console.error('[REGISTER]', err.message);
        res.status(400).json({ error: 'Date invalide' });
    }
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip;

    if (!email || !password) {
        return res.status(400).json({ error: 'Invalid credentials' });
    }

    try {
        const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

        if (user && user.locked_until && new Date(user.locked_until) > new Date()) {
            logAudit(user.id, 'LOGIN_BLOCKED', ip);
            return res.status(429).json({ error: 'Cont blocat temporar. Reincearca mai tarziu.' });
        }

        const fakeHash = '$2a$12$abcdefghijklmnopqrstuuFakeHashForTimingAttackPrevention';
        const hashToCompare = user ? user.password_hash : fakeHash;
        const valid = await bcrypt.compare(password, hashToCompare);

        if (!user || !valid) {
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
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        db.prepare(
            'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?'
        ).run(user.id);

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

router.post('/logout', (req, res) => {
    const userId = req.session.userId;
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Eroare logout' });
        }
        res.clearCookie('sid');
        logAudit(userId, 'LOGOUT', req.ip);
        res.json({ message: 'Deconectat' });
    });
});

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
