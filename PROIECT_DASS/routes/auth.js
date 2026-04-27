const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../database');

// ============================================
// REGISTER — v1 vulnerabil
// ============================================
router.post('/register', (req, res) => {
    const { email, password } = req.body;

    // v1: fara validare parola (accepta "1" sau "abc")
    if (!email || !password) {
        return res.status(400).json({ error: 'Email si parola sunt obligatorii' });
    }

    // v1: parola stocata in CLAR (fara bcrypt)
    try {
        const stmt = db.prepare(
            'INSERT INTO users (email, password_hash) VALUES (?, ?)'
        );
        stmt.run(email, password); // <-- BUG intentionat: parola in clar

        db.prepare(
            'INSERT INTO audit_logs (action) VALUES (?)'
        ).run('REGISTER');

        res.json({ message: 'Cont creat cu succes' });
    } catch (err) {
        // v1: mesaj diferit daca userul exista deja — user enumeration!
        if (err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Email-ul este deja inregistrat' });
        }
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// LOGIN — v1 vulnerabil
// ============================================
router.post('/login', (req, res) => {
    const { email, password } = req.body;

    // v1: mesaje DIFERITE pentru user inexistent vs parola gresita
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    if (!user) {
        // v1: dezvaluie ca userul nu exista — user enumeration!
        return res.status(401).json({ error: 'Utilizatorul nu exista' });
    }

    // v1: comparare parola in clar
    if (password !== user.password_hash) {
        return res.status(401).json({ error: 'Parola incorecta' });
    }

    // v1: sesiune fara regenerare ID
    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.role = user.role;

    db.prepare(
        'INSERT INTO audit_logs (user_id, action) VALUES (?, ?)'
    ).run(user.id, 'LOGIN');

    res.json({ message: 'Autentificat cu succes', role: user.role });
});

// ============================================
// LOGOUT
// ============================================
router.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Deconectat' });
});

// ============================================
// PROFIL (ruta protejata)
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