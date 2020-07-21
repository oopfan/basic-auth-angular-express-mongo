import * as express from 'express';
import {Application} from "express";
import {signinUser, signedinUser, signoutUser, signupUser, availableUser} from './routes';

const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');

const corsOptions = {
    origin: 'http://localhost:4200',
    credentials: true
};

const sessionOptions = {
    secret: 'ZLv3Lykqci5nGod(jix@lWCtB0GxGsumtG4K(y#c2)fBKHT7tk',
    resave: false,
    saveUninitialized: false,
    cookie: {
        sameSite: 'lax',    // Override to satisfy Firefox
        httpOnly: false,    // The default is true
        maxAge: 2592000000  // 30 days
    }
};

const app: Application = express();
app.use(session(sessionOptions));
app.use(cors(corsOptions));
app.use(bodyParser.json());

app.route('/api/auth/signin').post(signinUser);
app.route('/api/auth/signedin').get(signedinUser);
app.route('/api/auth/signout').post(signoutUser);
app.route('/api/auth/signup').post(signupUser);
app.route('/api/auth/username').post(availableUser);

const httpServer = app.listen(9000, () => {
    console.log("HTTP REST API Server running at http://localhost:" + httpServer.address()["port"]);
});
