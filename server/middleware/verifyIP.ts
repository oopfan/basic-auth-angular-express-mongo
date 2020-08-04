import { Request, Response, NextFunction } from 'express';

export function verifyIP(req: Request, res: Response, next: NextFunction) {
    const authorizedData = req['user'];
    if (!authorizedData || authorizedData.ip !== req.ip) return res.status(403).json({ message: 'Invalid IP address' });
    next();
}
