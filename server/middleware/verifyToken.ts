import { Request, Response, NextFunction } from 'express';
import * as jwt from 'express-jwt';

const jwtOptions = {
    secret: process.env.AUTH_SECRET || 'privatekey',
    algorithms: ['HS256'],
    issuer: process.env.TOKEN_ISSUER || 'myapp'
}
const middleware = jwt(jwtOptions);

export const verifyToken = (req: Request, res: Response, next: NextFunction) => {
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
