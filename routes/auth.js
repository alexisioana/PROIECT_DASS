const express = require('express');
const router = express.Router();
const db = require('../database');

router.post('/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email sau parola lipsa' });
    }
    try {
        db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, password);
        res.json({ message: 'User creat cu succes' });
    } catch (err) {
        res.status(400).json({ error: 'Email deja existent' });
    }
});

router.post('/login', (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
        return res.status(404).json({ error: 'Utilizatorul nu exista' });
    }
    if (user.password_hash !== password) {
        return res.status(401).json({ error: 'Parola gresita' });
    }
    req.session.userId = user.id;
    req.session.email = user.email;
    res.json({ message: 'Login reusit' });
});

router.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Deconectat' });
});

router.get('/profile', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Neautentificat' });
    }
    const user = db.prepare('SELECT id, email, role FROM users WHERE id = ?').get(req.session.userId);
    res.json(user);
});

module.exports = router;
