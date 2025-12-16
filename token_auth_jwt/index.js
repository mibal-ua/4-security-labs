require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const users = [
    { login: 'Login',  password: 'Password',  username: 'Username'  },
    { login: 'Login1', password: 'Password1', username: 'Username1' },
];

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;

const auth = (req, res, next) => {
    const header = req.get('Authorization') || '';
    const [scheme, token] = header.split(' ');

    if (!/^Bearer$/i.test(scheme) || !token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const user = users.find(u => u.login === login && u.password === password);
    if (!user) {
        return res.status(401).send();
    }

    const token = jwt.sign(
        { login: user.login, username: user.username },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({ token, username: user.username });
});

app.get('/api/me', auth, (req, res) => {
    res.json({ username: req.user.username, login: req.user.login });
});

app.listen(port, () => {
    console.log(`JWT app listening on port ${port}`);
});