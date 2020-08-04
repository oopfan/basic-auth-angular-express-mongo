import * as express from 'express';
import * as cors from 'cors';
import * as auth from './auth/router';

const corsOptions = {
    origin: process.env.CORS_ORIGIN,
    credentials: true
};

export const app = express();
app.use(cors(corsOptions));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/api/auth', auth.router);
