import { Request, Response, NextFunction } from 'express';
import * as mongoose from 'mongoose';
import * as jwt from 'jsonwebtoken';

const logError = (message: string) => {
    console.error(message);
}

const signAccessToken = (payload: any) => {
    return jwt.sign(payload, process.env.TOKEN_KEY, { issuer: process.env.TOKEN_ISSUER, subject: process.env.TOKEN_SUBJECT_ACCESS, expiresIn: process.env.TOKEN_EXPIRATION_ACCESS })    
}

const signRefreshToken = (payload: any) => {
    return jwt.sign(payload, process.env.TOKEN_KEY, { issuer: process.env.TOKEN_ISSUER, subject: process.env.TOKEN_SUBJECT_REFRESH, expiresIn: process.env.TOKEN_EXPIRATION_REFRESH })    
}

const verifyAccessToken = (token: string) => {
    return jwt.verify(token, process.env.TOKEN_KEY, { issuer: process.env.TOKEN_ISSUER, subject: process.env.TOKEN_SUBJECT_ACCESS });
}

const verifyRefreshToken = (token: string) => {
    return jwt.verify(token, process.env.TOKEN_KEY, { issuer: process.env.TOKEN_ISSUER, subject: process.env.TOKEN_SUBJECT_REFRESH });
}

const protectedResource = (res: Response) => {
    const message = 'Protected resource';
    logError (message);
    return res.status(403).json({ message });
}

const usernameInUse = (res: Response) => {
    logError('Username in use');
    return res.status(422).json({username: 'Username in use'});
}
const usernameNotFoundPasswordInvalid = (res: Response) => {
    logError('Username not found and/or invalid password');
    return res.status(422).json({username: 'Username not found', password: 'Invalid password'});
}

const emailInUse = (res: Response) => {
    logError('Email in use');
    return res.status(422).json({email: 'Email in use'});
}

const usernameFoundPasswordInvalid = (res: Response) => {
    logError('Username or email already exists or invalid password');
    return res.status(422).json({username: 'Username or email already exists', password: 'Invalid password'});
}

const errorAccessingUserDatabase = (res: Response) => {
    const message = 'Error accessing user database';
    logError (message);
    return res.status(500).json({ message });
}

const errorCreatingToken = (res: Response) => {
    const message = 'Error creating token';
    logError (message);
    return res.status(500).json({ message })
}

const invalidToken = (res: Response) => {
    const message = 'Invalid token';
    logError (message);
    return res.status(403).json({ message })
}

const expiredToken = (res: Response) => {
    const message = 'Expired token';
    logError (message);
    return res.status(403).json({ message });
}

const invalidIPAddress = (res: Response) => {
    const message = 'Invalid IP address';
    logError (message);
    return res.status(403).json({ message });
}

const cannotChangePasswordForAnotherUser = (res: Response) => {
    const message = 'Cannot change password for another user';
    logError (message);
    return res.status(422).json({ message });
}

mongoose.connect(process.env.MONGO_CONNECT, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
});

interface IUser extends mongoose.Document {
    username: string,
    email: string,
    password: string,
    role: string
}

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true }
});

const UserModel = mongoose.model<IUser>('User', UserSchema);

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
        if (err.name == 'TokenExpiredError') return expiredToken(res);
        return invalidToken(res);
    }

    if (authorizedData.ip != req.ip) return invalidIPAddress(res);

    const payload = {
        username: authorizedData.username,
        role: authorizedData.role,
        ip: authorizedData.ip
    }

    try {
        token = signAccessToken(payload);
    }
    catch(err) {
        return errorCreatingToken(res);
    }

    res.status(200).json({ _t: token });
}

export async function authUsername(req: Request, res: Response) {
    const { body } = req;
    const { username } = body;

    let [err, user] = await handle(UserModel.findOne({ username }));
    if (err) return errorAccessingUserDatabase(res);

    if (user) return usernameInUse(res);
    res.status(200).json({available: true});
}

export async function authEmail(req: Request, res: Response) {
    const { body } = req;
    const { email } = body;

    let [err, user] = await handle(UserModel.findOne({ email }));
    if (err) return errorAccessingUserDatabase(res);

    if (user) return emailInUse(res);
    res.status(200).json({available: true});
}

export async function authSignup(req: Request, res: Response) {
    const { body } = req;
    const { username } = body;
    let { email } = body;
    const { password } = body;
    const { passwordConfirmation } = body;

    if (username === undefined || email === undefined || password === undefined || passwordConfirmation === undefined) return usernameFoundPasswordInvalid(res);
    email = body.email.toLowerCase();
    
    // Check if email already in use:
    let [err, user] = await handle(UserModel.findOne({ email }));
    if (err) return errorAccessingUserDatabase(res);
    if (user) return usernameFoundPasswordInvalid(res);

    // Check that username does not exist:
    [err, user] = await handle(UserModel.findOne({ username }));
    if (err) return errorAccessingUserDatabase(res);
    if (user || password != passwordConfirmation) return usernameFoundPasswordInvalid(res);

    const newUser = new UserModel({
        username,
        email,
        password,
        role: roleFromEmail(email)
    });

    [err, user] = await handle(newUser.save());
    if (err) return errorAccessingUserDatabase(res);

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
        return errorCreatingToken(res);
    }

    res.status(200).json({ _t: token });
}

export async function authSignin(req: Request, res: Response) {
    const { body } = req;
    const { username } = body;
    const { password } = body;

    let [err, user] = await handle(UserModel.findOne({ username }));
    if (err) return errorAccessingUserDatabase(res);

    if (!user || user.username != username || user.password != password) {
        return usernameNotFoundPasswordInvalid(res);
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
        return errorCreatingToken(res);
    }

    res.status(200).json({ _t: token });
}

export function authSignout(req: Request, res: Response) {
    console.log('authSignout');
    const accessToken = req['token'];

    let authorizedData: any;
    try {
        authorizedData = verifyAccessToken(accessToken);
    }
    catch(err) {
        if (err.name == 'TokenExpiredError') return expiredToken(res);
        return invalidToken(res);
    }

    if (authorizedData.ip != req.ip) return invalidIPAddress(res);

    res.status(200).json({ authenticated: false, username: '' });
}

export function authSignedin(req: Request, res: Response) {
    const accessToken = req['token'];

    let authorizedData: any;
    try {
        authorizedData = verifyAccessToken(accessToken);
    }
    catch(err) {
        return res.status(200).json({ authenticated: false, username: '' });
    }

    res.status(200).json({ authenticated: true, username: authorizedData.username });
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
        if (err.name == 'TokenExpiredError') return expiredToken(res);
        return invalidToken(res);
    }

    if (authorizedData.ip != req.ip) return invalidIPAddress(res);
    if (authorizedData.username != username) return cannotChangePasswordForAnotherUser(res);

    let [err, user] = await handle(UserModel.findOne({ username }));
    if (err) return errorAccessingUserDatabase(res);

    if (!user || user.username != username || user.password != password || newPassword != newConfirmation) {
        return usernameNotFoundPasswordInvalid(res);
    }

    [err, user] = await handle(user.updateOne({ password: newPassword }));
    if (err) return errorAccessingUserDatabase(res);

    res.status(200).json({});
}

export function checkToken(req: Request, res: Response, next: NextFunction) {
    const header = req.headers['authorization'];
    if (typeof header !== 'undefined') {
        const bearer = header.split(' ');
        const token = bearer[1];
        req['token'] = token;
        next();
    }
    else
        protectedResource(res);
}

function roleFromEmail(email: string): string {
    return (email === process.env.ADMIN_EMAIL) ? 'Admin' : 'Guest';
}
