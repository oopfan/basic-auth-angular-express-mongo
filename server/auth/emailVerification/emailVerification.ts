import { Request, Response } from 'express';
import * as fs from 'fs';
import * as _ from 'underscore';
import * as jwt from 'jsonwebtoken';
import * as emailNewAccount from '../emailNewAccount/emailNewAccount';
import { sendMail } from '../sendMail';
import * as error from '../../errors';
import { UserModel } from '../../users/model';

const signEmailToken = (payload: any) => {
    return jwt.sign(payload, process.env.EMAIL_SECRET,
        {
            issuer: process.env.TOKEN_ISSUER,
            subject: process.env.TOKEN_SUBJECT_EMAIL,
            expiresIn: process.env.TOKEN_EXPIRATION_EMAIL
        }
    );
}

const verifyEmailToken = (token: string) => {
    return jwt.verify(token, process.env.EMAIL_SECRET, { issuer: process.env.TOKEN_ISSUER, subject: process.env.TOKEN_SUBJECT_EMAIL });
}

const handle = (promise) => {
    return promise
        .then(data => ([undefined, data]))
        .catch(error => Promise.resolve([error, undefined]));
}

export function send(email: string) {
    let emailToken: string;
    try {
        const emailPayload = {
            email
        };
        emailToken = signEmailToken(emailPayload);
    }
    catch(err) {
        throw new Error(error.ErrorCreatingToken);
    }

    const html = getHtml(emailToken);
    var mailOptions = {
        from: process.env.ADMIN_EMAIL,
        to: email,
        subject: 'New Account Verification',
        html: html
    };
    return sendMail(mailOptions);   // returns a promise
}

// This handler needs to be tested thoroughly on error conditions.
// Most likely scenario is the user verifies after the 24-hour expiration period.
export async function handler(req: Request, res: Response) {
    const emailToken = req.query.token.toString();

    let authorizedData: any;
    try {
        authorizedData = verifyEmailToken(emailToken);
    }
    catch(err) {
        if (err.name == 'TokenExpiredError') return error.sendResponse(res, error.ErrorExpiredToken);
        return error.sendResponse(res, error.ErrorInvalidToken);
    }

    const emailAddress = authorizedData.email;
    if (!emailAddress) return error.sendResponse(res, error.ErrorUnableToVerifyEmail);

    let [err, user] = await handle(UserModel.findOne({ email: emailAddress }));
    if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);
    if (!user) return error.sendResponse(res, error.ErrorUnableToVerifyEmail);

    if (!user.activated) {
        [err, user] = await handle(user.updateOne({ activated: true }));
        if (err) return error.sendResponse(res, error.ErrorAccessingUserDatabase);
    
        [err, user] = await handle(emailNewAccount.send(emailAddress));
        if (err) console.log('Error sending New Account creation email to administrator');
    
        return res.redirect(process.env.APP_URL + '/welcome/2');
    }

    res.redirect(process.env.APP_URL);
}

function getHtml(emailToken: string) {
    const html = fs.readFileSync(__dirname + '/emailVerification.html', {encoding: 'utf8'});
    const settings: _.TemplateSettings = { interpolate: /\{\{(.+?)\}\}/g };
    const template = _.template(html, settings);

    const model = {
        verifyUrl: process.env.APP_URL + '/api/auth/verify-email?token=' + encodeURIComponent(emailToken),
        title: process.env.APP_NAME,
        subTitle: 'Thanks for signing up!',
        body: 'Please verify your email address by clicking the button below. If you received this email in error please disregard.'
    };

    return template(model);
}
