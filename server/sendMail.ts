import * as nodemailer from 'nodemailer';
import * as smtpTransport from 'nodemailer-smtp-transport';

export function sendMail(mailOptions: any) {
    const smtpConfig = {
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT),
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    };
    const transporter = nodemailer.createTransport(smtpTransport(smtpConfig));
    return transporter.sendMail(mailOptions);   // returns a promise
}
