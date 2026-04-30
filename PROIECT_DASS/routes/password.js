const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../database');

// ============================================
// CONSTANTE
// ============================================
const TOKEN_EXPIRY_MINUTES = 15;
const PASSWORD_MIN_LENGTH = 8;
const BCRYPT_ROUNDS = 12;

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
    } catch (e) { /* ignore */ }
}

// ============================================
// FORGOT PASSWORD — v2 SECURIZAT
// ============================================
router.post('/forgot', (req, res) => {
    const { email } = req.body;
    const ip = req.ip;

    if (!email) {
        return res.status(400).json({ error: 'Email obligatoriu' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    if (user) {
        // FIX 4.6: token criptografic random (32 bytes hex)
        const token = crypto.randomBytes(32).toString('hex');
        // FIX 4.6: stocam HASH-ul tokenului in DB (nu tokenul in clar)
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

        // FIX 4.6: expirare scurta (15 min)
        const expiresAt = new Date(Date.now() + TOKEN_EXPIRY_MINUTES * 60 * 1000).toISOString();

        // Invalidam orice token anterior pentru acest user
        db.prepare(
            'UPDATE reset_tokens SET used = 1 WHERE user_id = ? AND used = 0'
        ).run(user.id);

        db.prepare(
            'INSERT INTO reset_tokens (user_id, token, expires_at, used) VALUES (?, ?, ?, 0)'
        ).run(user.id, tokenHash, expiresAt);

        logAudit(user.id, 'PASSWORD_RESET_REQUEST', ip);

        // In productie: email cu link. Aici (laborator) il afisam in consola serverului.
        console.log(`[RESET] Token pentru ${email}: ${token}`);
    } else {
        logAudit(null, 'PASSWORD_RESET_REQUEST_UNKNOWN', ip);
    }

    // FIX 4.4 + 4.6: raspuns IDENTIC pentru user existent / inexistent
    res.json({
        message: 'Daca emailul exista, vei primi un link de resetare'
    });
});

// ============================================
// RESET PASSWORD — v2 SECURIZAT
// ============================================
router.post('/reset', async (req, res) => {
    const { token, newPassword } = req.body;
    const ip = req.ip;

    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Date invalide' });
    }

    // FIX 4.1: validare parola
    const pwdError = validatePassword(newPassword);
    if (pwdError) {
        return res.status(400).json({ error: pwdError });
    }

    try {
        // Cautam dupa hash-ul tokenului
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const record = db.prepare(
            'SELECT * FROM reset_tokens WHERE token = ?'
        ).get(tokenHash);

        if (!record) {
            logAudit(null, 'PASSWORD_RESET_INVALID_TOKEN', ip);
            return res.status(400).json({ error: 'Token invalid sau expirat' });
        }

        // FIX 4.6: verificare "used"
        if (record.used) {
            logAudit(record.user_id, 'PASSWORD_RESET_TOKEN_REUSED', ip);
            return res.status(400).json({ error: 'Token invalid sau expirat' });
        }

        // FIX 4.6: verificare expirare
        if (new Date(record.expires_at) < new Date()) {
            logAudit(record.user_id, 'PASSWORD_RESET_TOKEN_EXPIRED', ip);
            return res.status(400).json({ error: 'Token invalid sau expirat' });
        }

        // FIX 4.2: parola noua hash-uita
        const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

        db.prepare('UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?')
            .run(hash, record.user_id);

        // FIX 4.6: marcam tokenul ca folosit (one-time use)
        db.prepare('UPDATE reset_tokens SET used = 1 WHERE id = ?').run(record.id);

        logAudit(record.user_id, 'PASSWORD_RESET_SUCCESS', ip);

        res.json({ message: 'Parola a fost resetata cu succes' });
    } catch (err) {
        console.error('[RESET]', err.message);
        res.status(500).json({ error: 'Eroare server' });
    }
});

module.exports = router;
