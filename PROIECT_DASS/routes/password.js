const express = require('express');
const router = express.Router();
const db = require('../database');

// ============================================
// FORGOT PASSWORD — v1 vulnerabil
// ============================================
router.post('/forgot', (req, res) => {
    const { email } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    if (!user) {
        // v1: confirma ca emailul NU exista — user enumeration!
        return res.status(404).json({ error: 'Email negasit' });
    }

    // v1: token predictibil — bazat pe timestamp
    const token = Date.now().toString();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(); // 24h

    db.prepare(
        'INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
    ).run(user.id, token, expiresAt);

    // In productie s-ar trimite email; aici returnam tokenul direct (pentru PoC)
    res.json({
        message: 'Token generat',
        reset_link: `http://localhost:3000/reset?token=${token}` // v1: expus direct
    });
});

// ============================================
// RESET PASSWORD — v1 vulnerabil
// ============================================
router.post('/reset', (req, res) => {
    const { token, newPassword } = req.body;

    // v1: token reutilizabil — nu verifica campul "used"
    const record = db.prepare(
        'SELECT * FROM reset_tokens WHERE token = ?'
    ).get(token);

    if (!record) {
        return res.status(400).json({ error: 'Token invalid' });
    }

    // v1: fara verificare expirare

    // v1: parola salvata in clar
    db.prepare(
        'UPDATE users SET password_hash = ? WHERE id = ?'
    ).run(newPassword, record.user_id);

    res.json({ message: 'Parola resetata' });
});

module.exports = router;