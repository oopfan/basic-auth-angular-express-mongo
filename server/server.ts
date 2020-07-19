import * as express from 'express';
import {Application} from "express";
import {signinUser} from './signin.route';
import {signedinUser} from './signedin.route';
import {signoutUser} from './signout.route';
import {signupUser} from './signup.route';
import {availableUser} from './username.route';

const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser')

const corsOptions = {
    origin: 'http://localhost:4200',
    credentials: true
};
  
const app: Application = express();
app.use(cors(corsOptions));
app.use(cookieParser());
app.use(bodyParser.json());

app.route('/api/auth/signin').post(signinUser);
app.route('/api/auth/signedin').get(signedinUser);
app.route('/api/auth/signout').post(signoutUser);
app.route('/api/auth/signup').post(signupUser);
app.route('/api/auth/username').post(availableUser);

const httpServer = app.listen(9000, () => {
    console.log("HTTP REST API Server running at http://localhost:" + httpServer.address()["port"]);
});
