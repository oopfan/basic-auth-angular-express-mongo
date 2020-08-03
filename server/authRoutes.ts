import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';
import * as emailVerification from './emailVerification/emailVerification';
import * as error from './errors';
import { UserModel } from './userModel';

const signAccessToken = (payload: any) => {
    return jwt.sign(payload, process.env.AUTH_SECRET,
        {
            issuer: process.env.TOKEN_ISSUER,
            // expiresIn: process.env.TOKEN_EXPIRATION_ACCESS
        }
    );
}

const handle = (promise) => {
    return promise
        .then(data => ([undefined, data]))
        .catch(error => Promise.resolve([error, undefined]));
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
        isAdmin: roleFromEmail(email),
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
        isAdmin: user.isAdmin,
        ip: req.ip
    }

    let token: string;
    try {
        token = signAccessToken(payload);
    }
    catch(err) {
        return error.sendResponse(res, error.ErrorCreatingToken);
    }

    res.status(200).json({ accessToken: token, activated: user.activated, username: user.username, isAdmin: user.isAdmin });
}

export function authSignout(req: Request, res: Response) {
    res.status(200).json({ authenticated: false, activated: false, username: '', isAdmin: false });
}

export async function authSignedin(req: Request, res: Response) {
    let authorizedData = req['user'];

    let [err, user] = await handle(UserModel.findOne({ username: authorizedData.username }));
    if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);

    if (!user) {
        return error.sendResponse(res, error.ErrorUsernameNotFoundPasswordInvalid);
    }

    res.status(200).json({ authenticated: true, activated: user.activated, username: user.username, isAdmin: user.isAdmin });
}

export async function authChgpwd(req: Request, res: Response) {
    const { body } = req;
    const { username, password, newPassword, newConfirmation } = body;

    let authorizedData = req['user'];
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

export function verifyIP(req: Request, res: Response, next: NextFunction) {
    const authorizedData = req['user'];
    if (authorizedData.ip !== req.ip) return error.sendResponse(res, error.ErrorInvalidIPAddress);
    next();
}

function roleFromEmail(email: string): boolean {
    return email === process.env.ADMIN_EMAIL;
}
