import * as fs from 'fs';
import * as _ from 'underscore';
import { sendMail } from '../sendMail';

export function send(emailAddress: string) {
    const html = getHtml(emailAddress);
    var mailOptions = {
        from: process.env.ADMIN_EMAIL,
        to: process.env.ADMIN_EMAIL,
        subject: 'New Account',
        html: html
    };
    return sendMail(mailOptions);   // returns a promise
}

function getHtml(emailAddress: string) {
    const html = fs.readFileSync(__dirname + '/emailNewAccount.html', {encoding: 'utf8'});
    const settings: _.TemplateSettings = { interpolate: /\{\{(.+?)\}\}/g };
    const template = _.template(html, settings);

    const model = {
        title: process.env.APP_NAME,
        subTitle: 'New Account!',
        body: emailAddress
    };

    return template(model);
}
