import * as express from 'express';
import * as cors from 'cors';
import { authSignup, authSignin, authSignout, authChgpwd, checkToken, authAccess, authUsername, authEmail, authSignedin } from './routes';

const corsOptions = {
    origin: 'http://localhost:4200',
    credentials: true
};

const app = express();
const port = 9000;

app.use(cors(corsOptions));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.route('/api/auth/access').post(checkToken, authAccess);
app.route('/api/auth/username').post(authUsername);
app.route('/api/auth/email').post(authEmail);
app.route('/api/auth/signup').post(authSignup);
app.route('/api/auth/signin').post(authSignin);
app.route('/api/auth/signout').post(checkToken, authSignout);
app.route('/api/auth/signedin').post(checkToken, authSignedin);
app.route('/api/auth/chgpwd').post(checkToken, authChgpwd);

const httpServer = app.listen(port, () => {
    console.log("HTTP REST API Server running at http://localhost:" + httpServer.address()["port"]);
});
