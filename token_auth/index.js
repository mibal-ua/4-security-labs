const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const {EncryptJWT, jwtDecrypt} = require('jose');

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

require('dotenv').config();

const port = process.env.PORT || 3000;
const app = express();

const client = jwksClient({
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
});

const secret = Buffer.from(process.env.JWT_ENC_SECRET, 'base64');

const encryptToken = async (payload, ttl = '1h') => new EncryptJWT(payload)
    .setProtectedHeader({alg: 'dir', enc: 'A256GCM'})
    .setIssuedAt()
    .setExpirationTime(ttl)
    .encrypt(secret);

const decryptToken = async (jweToken) => {
    const {payload} = await jwtDecrypt(jweToken, secret);
    return payload;
};

const getKey = (header, callback) => {
    client.getSigningKey(header.kid, (err, key) => {
        if (err) return callback(err);

        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
};

const checkJwt = (req, res, next) => {
    const token = req.session.access_token;

    if (!token) return res.status(401).json({error: 'No token found'});

    jwt.verify(token, getKey, {
        audience: process.env.AUTH0_AUDIENCE,
        issuer: `https://${process.env.AUTH0_DOMAIN}/`,
        algorithms: ['RS256']
    }, (err, decoded) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.status(401).json({error: 'Invalid token'});
        }

        req.user = decoded;
        next();
    });
};

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

const SESSION_KEY = 'Authorization';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());
            console.log(this.#sessions);
        } catch (e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
    }

    set(key, value) {
        if (!value) value = {};
        this.#sessions[key] = value;
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    init(res) {
        const sessionId = uuid.v4();
        this.set(sessionId);
        return sessionId;
    }

    destroy(req, res) {
        const sessionId = req.sessionId;
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session();

app.use((req, res, next) => {
    let currentSession = {};
    let sessionId = req.get(SESSION_KEY);

    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
        }
    } else {
        sessionId = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(req, () => {
        const currentSession = req.session;
        const sessionId = req.sessionId;
        sessions.set(sessionId, currentSession);
    });

    next();
});

app.get('/', (req, res) => {
    if (req.session.username) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body;

    try {
        const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
            method: 'POST',
            headers: {'content-type': 'application/json'},
            body: JSON.stringify({
                grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
                username: login,
                password: password,
                client_id: process.env.AUTH0_CLIENT_ID,
                client_secret: process.env.AUTH0_CLIENT_SECRET,
                realm: process.env.AUTH0_REALM,
                scope: 'openid profile email offline_access',
                audience: process.env.AUTH0_AUDIENCE
            })
        });

        if (!response.ok) return res.status(401).json({error: 'Invalid credentials'});

        const data = await response.json();
        const {access_token, id_token, refresh_token, expires_in} = data;
        const decoded = jwt.decode(id_token);

        const payload = {
            ...decoded,
            access_token,
            refresh_token,
        };

        const jwe = await encryptToken(payload, '1h');

        req.session.username = login;
        req.session.access_token = jwe;
        req.session.refresh_token = refresh_token;
        req.session.expires_at = Date.now() + expires_in * 1000;
        req.session.issued_at = Date.now();

        res.json({
            message: 'Login successful',
            sessionId: req.sessionId,
            username: login,
            token: jwe,
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({error: 'Internal server error'});
    }
});

app.post('/api/register', async (req, res) => {
    const {email, password} = req.body;

    try {
        const mgmtTokenResp = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
            method: 'POST',
            headers: {'content-type': 'application/json'},
            body: JSON.stringify({
                client_id: process.env.AUTH0_CLIENT_ID,
                client_secret: process.env.AUTH0_CLIENT_SECRET,
                audience: `https://${process.env.AUTH0_DOMAIN}/api/v2/`,
                grant_type: 'client_credentials'
            })
        });

        const {access_token: mgmtToken} = await mgmtTokenResp.json();

        const createResp = await fetch(`https://${process.env.AUTH0_DOMAIN}/api/v2/users`, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                'Authorization': `Bearer ${mgmtToken}`
            },
            body: JSON.stringify({
                email,
                password,
                connection: process.env.AUTH0_REALM
            })
        });

        if (!createResp.ok) {
            const err = await createResp.text();
            return res.status(400).send(err);
        }

        const user = await createResp.json();
        res.json({message: 'User created', user});

    } catch (e) {
        console.error('Register error:', e);
        res.status(500).json({error: 'Internal server error'});
    }
});

app.get('/api/check-token', async (req, res) => {
    const session = req.session;

    if (!session.access_token) {
        return res.status(401).json({error: 'Not logged in'});
    }

    try {
        const payload = await decryptToken(session.access_token);
        let {access_token, refresh_token, exp, username, sub, email, name} = payload;

        let expiresIn = (payload.expires_at || exp * 1000) - Date.now();

        if (expiresIn < 60 * 1000) {
            const refreshResp = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
                method: 'POST',
                headers: {'content-type': 'application/json'},
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    client_id: process.env.AUTH0_CLIENT_ID,
                    client_secret: process.env.AUTH0_CLIENT_SECRET,
                    refresh_token: session.refresh_token
                })
            });

            const data = await refreshResp.json();

            if (data.access_token) {
                access_token = data.access_token;
                expiresIn = data.expires_in * 1000;

                const newPayload = {
                    ...payload,
                    access_token,
                    expires_at: Date.now() + expiresIn,
                };

                const newJwe = await encryptToken(newPayload, '1h');

                session.access_token = newJwe;
                session.expires_at = newPayload.expires_at;
                sessions.set(req.sessionId, session);

                return res.json({
                    message: 'Token refreshed (and encrypted as JWE)',
                    token: newJwe,
                    user: {sub, email, name, username},
                });
            }
        }

        res.json({
            message: 'Token is valid and signature verified',
            token: session.access_token,
            expires_in: Math.floor(expiresIn / 1000),
            user: payload,
        });

    } catch (err) {
        console.error('JWE decryption error:', err);
        return res.status(401).json({error: 'Invalid or expired JWE'});
    }
});
app.post('/debug/set-token', (req, res) => {
    const {token} = req.body;
    if (!token) return res.status(400).json({error: 'Provide token in body'});

    req.session.access_token = token;
    req.session.issued_at = Date.now();
    req.session.expires_at = Date.now() + 60 * 1000;

    sessions.set(req.sessionId, req.session);
    res.json({message: 'Token set for testing', sessionId: req.sessionId});
});


app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
});