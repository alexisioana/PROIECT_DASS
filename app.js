const express = require('express');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');

const authRoutes = require('./routes/auth');
const passwordRoutes = require('./routes/password');
const ticketsRoutes = require('./routes/tickets');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true,
    cookie: {
        httpOnly: false,
        secure: false,
        sameSite: false,
        maxAge: 1000 * 60 * 60 * 24 * 30
    }
}));

app.use('/api/auth', authRoutes);
app.use('/api/password', passwordRoutes);
app.use('/api/tickets', ticketsRoutes);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
