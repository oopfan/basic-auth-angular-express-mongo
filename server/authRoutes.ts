import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';
import * as emailVerification from './emailVerification/emailVerification';
import * as error from './errors';
import { UserModel } from './userModel';

const signAccessToken = (payload: any) => {
    return jwt.sign(payload, process.env.AUTH_SECRET,
        {
            issuer: process.env.TOKEN_ISSUER,
            subject: process.env.TOKEN_SUBJECT_ACCESS,
            expiresIn: process.env.TOKEN_EXPIRATION_ACCESS
        }
    );
}

const signRefreshToken = (payload: any) => {
    return jwt.sign(payload, process.env.AUTH_SECRET,
        {
            issuer: process.env.TOKEN_ISSUER,
            subject: process.env.TOKEN_SUBJECT_REFRESH,
            expiresIn: process.env.TOKEN_EXPIRATION_REFRESH
        }
    );
}

const verifyAccessToken = (token: string) => {
    return jwt.verify(token, process.env.AUTH_SECRET,
        {
            issuer: process.env.TOKEN_ISSUER,
            subject: process.env.TOKEN_SUBJECT_ACCESS
        }
    );
}

const verifyRefreshToken = (token: string) => {
    return jwt.verify(token, process.env.AUTH_SECRET,
        {
            issuer: process.env.TOKEN_ISSUER,
            subject: process.env.TOKEN_SUBJECT_REFRESH
        }
    );
}

const handle = (promise) => {
    return promise
        .then(data => ([undefined, data]))
        .catch(error => Promise.resolve([error, undefined]));
}

export function authAccess(req: Request, res: Response) {
    // Returns either:
    //  403: { message: 'Expired token' }
    //  403: { message: 'Invalid token' }
    //  403: { message: 'Invalid IP address' }
    //  500: { message: 'Error creating token' }
    //  200: { _t: <token> }

    let token = req['token'];

    let authorizedData: any;
    try {
        authorizedData = verifyRefreshToken(token);
    }
    catch(err) {
        if (err.name == 'TokenExpiredError') return error.sendResponse(res, error.ErrorExpiredToken);
        return error.sendResponse(res, error.ErrorInvalidToken);
    }

    if (authorizedData.ip != req.ip) return error.sendResponse(res, error.ErrorInvalidIPAddress);

    const payload = {
        username: authorizedData.username,
        role: authorizedData.role,
        ip: authorizedData.ip
    }

    try {
        token = signAccessToken(payload);
    }
    catch(err) {
        return error.sendResponse(res, error.ErrorCreatingToken);
    }

    res.status(200).json({ _t: token });
}

export async function authUsername(req: Request, res: Response) {
    const { body } = req;
    const { username } = body;

    let [err, user] = await handle(UserModel.findOne({ username }));
    if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);

    if (user) return error.sendResponse(res, error.ErrorUsernameInUse);
    res.status(200).json({available: true});
}

export async function authEmail(req: Request, res: Response) {
    const { body } = req;
    const { email } = body;

    let [err, user] = await handle(UserModel.findOne({ email }));
    if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);

    if (user) return error.sendResponse(res, error.ErrorEmailInUse);
    res.status(200).json({available: true});
}

export async function authSignup(req: Request, res: Response) {
    console.log('authSignup');
    const { body } = req;
    const { username } = body;
    let { email } = body;
    const { password } = body;
    const { passwordConfirmation } = body;

    if (username === undefined || email === undefined || password === undefined || passwordConfirmation === undefined)
        return error.sendResponse(res, error.ErrorUsernameFoundPasswordInvalid);

    email = body.email.toLowerCase();
    
    // Check if email already in use:
    let [err, user] = await handle(UserModel.findOne({ email }));
    if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);
    if (user) return error.sendResponse(res, error.ErrorUsernameFoundPasswordInvalid);

    // Check that username does not exist:
    [err, user] = await handle(UserModel.findOne({ username }));
    if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);
    if (user || password != passwordConfirmation) return error.sendResponse(res, error.ErrorUsernameFoundPasswordInvalid);

    try {
        await emailVerification.send(email);
    }
    catch(e) {
        if (e.message === error.ErrorCreatingToken) return error.sendResponse(res, error.ErrorCreatingToken);
        return error.sendResponse(res, error.ErrorSendingEmail);
    }

    const newUser = new UserModel({
        username,
        email,
        password,
        role: roleFromEmail(email),
        activated: false,
        memberSince: Date.now()
    });

    [err, user] = await handle(newUser.save());
    if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);

    res.status(200).json({ message: 'Awaiting Verification' });
}

export async function authSignin(req: Request, res: Response) {
    const { body } = req;
    const { username } = body;
    const { password } = body;

    let [err, user] = await handle(UserModel.findOne({ username }));
    if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);

    if (!user || user.username != username || user.password != password) {
        return error.sendResponse(res, error.ErrorUsernameNotFoundPasswordInvalid);
    }

    const payload = {
        username: user.username,
        role: user.role,
        ip: req.ip
    }

    let token: string;
    try {
        token = signRefreshToken(payload);
    }
    catch(err) {
        return error.sendResponse(res, error.ErrorCreatingToken);
    }

    res.status(200).json({ refreshToken: token, activated: user.activated, username: user.username, role: user.role });
}

export function authSignout(req: Request, res: Response) {
    console.log('authSignout');
    const accessToken = req['token'];

    let authorizedData: any;
    try {
        authorizedData = verifyAccessToken(accessToken);
    }
    catch(err) {
        if (err.name == 'TokenExpiredError') return error.sendResponse(res, error.ErrorExpiredToken);
        return error.sendResponse(res, error.ErrorInvalidToken);
    }

    if (authorizedData.ip != req.ip) return error.sendResponse(res, error.ErrorInvalidIPAddress);

    res.status(200).json({ authenticated: false, activated: false, username: '', role: '' });
}

export async function authSignedin(req: Request, res: Response) {
    const accessToken = req['token'];

    let authorizedData: any;
    try {
        authorizedData = verifyAccessToken(accessToken);
    }
    catch(err) {
        if (err.name == 'TokenExpiredError') return error.sendResponse(res, error.ErrorExpiredToken);
        return error.sendResponse(res, error.ErrorInvalidToken);
    }

    let [err, user] = await handle(UserModel.findOne({ username: authorizedData.username }));
    if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);

    if (!user) {
        return error.sendResponse(res, error.ErrorUsernameNotFoundPasswordInvalid);
    }

    res.status(200).json({ authenticated: true, activated: user.activated, username: user.username, role: user.role });
}

export async function authChgpwd(req: Request, res: Response) {
    const { body } = req;
    const { username, password, newPassword, newConfirmation } = body;
    const accessToken = req['token'];

    let authorizedData: any;
    try {
        authorizedData = verifyAccessToken(accessToken);
    }
    catch(err) {
        if (err.name == 'TokenExpiredError') return error.sendResponse(res, error.ErrorExpiredToken);
        return error.sendResponse(res, error.ErrorInvalidToken);
    }

    if (authorizedData.ip != req.ip) return error.sendResponse(res, error.ErrorInvalidIPAddress);
    if (authorizedData.username != username) return error.sendResponse(res, error.ErrorCannotChangePasswordForAnotherUser);

    let [err, user] = await handle(UserModel.findOne({ username }));
    if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);

    if (!user || user.username != username || user.password != password || newPassword != newConfirmation) {
        return error.sendResponse(res, error.ErrorUsernameNotFoundPasswordInvalid);
    }

    [err, user] = await handle(user.updateOne({ password: newPassword }));
    if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);

    res.status(200).json({});
}

export function checkToken(req: Request, res: Response, next: NextFunction) {
    const header = req.headers['authorization'];
    if (typeof header === 'undefined') return error.sendResponse(res, error.ErrorProtectedResource);

    const bearer = header.split(' ');
    const token = bearer[1];
    req['token'] = token;
    next();
}

function roleFromEmail(email: string): string {
    return (email === process.env.ADMIN_EMAIL) ? 'Admin' : 'Guest';
}
