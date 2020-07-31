import { Request, Response, NextFunction } from 'express';
import * as fs from 'fs';
import * as mongoose from 'mongoose';
import * as jwt from 'jsonwebtoken';
import * as _ from 'underscore';
import * as nodemailer from 'nodemailer';
import * as smtpTransport from 'nodemailer-smtp-transport';

const logError = (message: string) => {
    console.error(message);
}

const signEmailToken = (payload: any) => {
    return jwt.sign(payload, process.env.EMAIL_SECRET, { issuer: process.env.TOKEN_ISSUER, subject: process.env.TOKEN_SUBJECT_EMAIL, expiresIn: process.env.TOKEN_EXPIRATION_EMAIL })
}

const signAccessToken = (payload: any) => {
    return jwt.sign(payload, process.env.AUTH_SECRET, { issuer: process.env.TOKEN_ISSUER, subject: process.env.TOKEN_SUBJECT_ACCESS, expiresIn: process.env.TOKEN_EXPIRATION_ACCESS })
}

const signRefreshToken = (payload: any) => {
    return jwt.sign(payload, process.env.AUTH_SECRET, { issuer: process.env.TOKEN_ISSUER, subject: process.env.TOKEN_SUBJECT_REFRESH, expiresIn: process.env.TOKEN_EXPIRATION_REFRESH })
}

const verifyEmailToken = (token: string) => {
    return jwt.verify(token, process.env.EMAIL_SECRET, { issuer: process.env.TOKEN_ISSUER, subject: process.env.TOKEN_SUBJECT_EMAIL });
}

const verifyAccessToken = (token: string) => {
    return jwt.verify(token, process.env.AUTH_SECRET, { issuer: process.env.TOKEN_ISSUER, subject: process.env.TOKEN_SUBJECT_ACCESS });
}

const verifyRefreshToken = (token: string) => {
    return jwt.verify(token, process.env.AUTH_SECRET, { issuer: process.env.TOKEN_ISSUER, subject: process.env.TOKEN_SUBJECT_REFRESH });
}

const unableToVerifyEmail = (res: Response) => {
    const message = 'Authentication failed, unable to verify email';
    logError (message);
    return res.status(422).json({ message });
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
    role: string,
    activated: boolean,
    memberSince: number
}

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true },
    activated: { type: Boolean, required: true },
    memberSince: { type: Number, required: true }
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
        role: roleFromEmail(email),
        activated: false,
        memberSince: Date.now()
    });

    [err, user] = await handle(newUser.save());
    if (err) return errorAccessingUserDatabase(res);

    const emailPayload = {
        email
    };
    let emailToken: string;
    try {
        emailToken = signEmailToken(emailPayload);
    }
    catch(err) {
        return errorCreatingToken(res);
    }

    const html = getEmailVerificationHtml(emailToken);
    var mailOptions = {
        from: process.env.ADMIN_EMAIL,
        to: email,
        subject: 'New Account Verification',
        html: html
    };
    smtpSendMail(mailOptions);

    res.status(200).json({ message: 'Awaiting Verification' });
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
        if (err.name == 'TokenExpiredError') return expiredToken(res);
        return invalidToken(res);
    }

    if (authorizedData.ip != req.ip) return invalidIPAddress(res);

    res.status(200).json({ authenticated: false, activated: false, username: '', role: '' });
}

export async function authSignedin(req: Request, res: Response) {
    const accessToken = req['token'];

    let authorizedData: any;
    try {
        authorizedData = verifyAccessToken(accessToken);
    }
    catch(err) {
        if (err.name == 'TokenExpiredError') return expiredToken(res);
        return invalidToken(res);
    }

    let [err, user] = await handle(UserModel.findOne({ username: authorizedData.username }));
    if (err) return errorAccessingUserDatabase(res);

    if (!user) {
        return usernameNotFoundPasswordInvalid(res);
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

function getEmailVerificationHtml(token: string) {
    const html = fs.readFileSync(__dirname + '/emailVerification.html', {encoding: 'utf8'});
    const settings: _.TemplateSettings = { interpolate: /\{\{(.+?)\}\}/g };
    const template = _.template(html, settings);

    const model = {
        verifyUrl: process.env.APP_URL + '/api/auth/verify-email?token=' + encodeURIComponent(token),
        title: process.env.APP_NAME,
        subTitle: 'Thanks for signing up!',
        body: 'Please verify your email address by clicking the button below. If you received this email in error please disregard.'
    };

    return template(model);
}

function getEmailNewAccountHtml(email: string) {
    const html = fs.readFileSync(__dirname + '/emailNewAccount.html', {encoding: 'utf8'});
    const settings: _.TemplateSettings = { interpolate: /\{\{(.+?)\}\}/g };
    const template = _.template(html, settings);

    const model = {
        title: process.env.APP_NAME,
        subTitle: 'New Account!',
        body: email
    };

    return template(model);
}

export async function authEmailVerification(req: Request, res: Response) {
    const emailToken = req.query.token.toString();

    let authorizedData: any;
    try {
        authorizedData = verifyEmailToken(emailToken);
    }
    catch(err) {
        if (err.name == 'TokenExpiredError') return expiredToken(res);
        return invalidToken(res);
    }

    const email = authorizedData.email;
    if (!email) return unableToVerifyEmail(res);

    let [err, user] = await handle(UserModel.findOne({ email }));
    if (err) return errorAccessingUserDatabase(res);
    if (!user) return unableToVerifyEmail(res);

    if (!user.activated) {
        [err, user] = await handle(user.updateOne({ activated: true }));
        if (err) return errorAccessingUserDatabase(res);
    
        const html = getEmailNewAccountHtml(email);
        var mailOptions = {
            from: process.env.ADMIN_EMAIL,
            to: process.env.ADMIN_EMAIL,
            subject: 'New Account',
            html: html
        };
        smtpSendMail(mailOptions);
    }

    res.redirect(process.env.APP_URL);
}

function smtpSendMail(mailOptions: any) {
    const smtpConfig = {
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT),
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    };
    var transporter = nodemailer.createTransport(smtpTransport(smtpConfig));
    transporter.sendMail(mailOptions, function(err, info) {
        if (err) {
            console.log('error sending email to ' + mailOptions.to);
        }
        else {
            console.log('sent email to ' + mailOptions.to + ' (' + info.response + ')');
        }
    });
};
