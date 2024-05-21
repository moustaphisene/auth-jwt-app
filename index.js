const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your_secret_key'; // Remplacez ceci par une clé secrète sécurisée

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Simuler une base de données utilisateur
const users = [
    {
        id: 1,
        username: 'testuser',
        password: bcrypt.hashSync('password123', 8) // Mot de passe hashé
    }
];

// Route de connexion
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(404).send('User not found');
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
        return res.status(401).send('Invalid password');
    }

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: 86400 }); // Expire dans 24 heures
    res.status(200).send({ auth: true, token });
});

// Middleware de vérification du token
function verifyToken(req, res, next) {
    const token = req.headers['x-access-token'];
    if (!token) {
        return res.status(403).send({ auth: false, message: 'No token provided' });
    }

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(500).send({ auth: false, message: 'Failed to authenticate token' });
        }
        req.userId = decoded.id;
        next();
    });
}

// Route de vérification de token
app.get('/me', verifyToken, (req, res) => {
    const user = users.find(u => u.id === req.userId);
    if (!user) {
        return res.status(404).send('User not found');
    }

    res.status(200).send(user);
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
