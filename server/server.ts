import * as dotenv from 'dotenv';
dotenv.config();

import * as mongoose from 'mongoose';
import * as express from 'express';
import * as jwt from 'express-jwt';
import * as cors from 'cors';
import { authSignup, authSignin, authSignout, authChgpwd, authUsername, authEmail, authSignedin, verifyIP } from './authRoutes';
import * as emailVerification from './emailVerification/emailVerification';

mongoose.connect(process.env.MONGO_CONNECT, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
});

const corsOptions = {
    origin: process.env.CORS_ORIGIN,
    credentials: true
};

const app = express();
const port = process.env.PORT;

app.use(cors(corsOptions));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const jwtOptions = {
    secret: process.env.AUTH_SECRET,
    algorithms: ['HS256'],
    issuer: process.env.TOKEN_ISSUER
}
const middleware = jwt(jwtOptions);

const verifyToken = (req, res, next) => {
    const handleErrorNext = err => {
        if (err) {
            if (err.name === 'UnauthorizedError') {
                if (err.inner.name === 'TokenExpiredError') return res.status(403).json({ message: 'Expired token' });
                return res.status(403).json({ message: 'Invalid token' });
            }
        }
        next(err);
    };
    middleware(req, res, handleErrorNext);
};

app.route('/api/auth/username').post(authUsername);
app.route('/api/auth/email').post(authEmail);
app.route('/api/auth/signup').post(authSignup);
app.route('/api/auth/signin').post(authSignin);
app.route('/api/auth/signout').post(verifyToken, verifyIP, authSignout);
app.route('/api/auth/signedin').post(verifyToken, verifyIP, authSignedin);
app.route('/api/auth/chgpwd').post(verifyToken, verifyIP, authChgpwd);
app.route('/api/auth/verify-email').get(emailVerification.handler);

app.listen(port, () => {
    console.log('Express server listening on port ' + port);
});
