const express = require('express');
const router = express.Router();
const db = require('../database');

router.post('/forgot', (req, res) => {
    const { email } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
        return res.status(404).json({ error: 'Emailul nu exista' });
    }
    const token = Date.now().toString();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    db.prepare('INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, token, expiresAt);
    res.json({ message: 'Token generat', token: token });
});

router.post('/reset', (req, res) => {
    const { token, newPassword } = req.body;
    const record = db.prepare('SELECT * FROM reset_tokens WHERE token = ?').get(token);
    if (!record) {
        return res.status(400).json({ error: 'Token invalid' });
    }
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newPassword, record.user_id);
    res.json({ message: 'Parola resetata' });
});

module.exports = router;
