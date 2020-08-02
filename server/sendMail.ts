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
    var transporter = nodemailer.createTransport(smtpTransport(smtpConfig));
    transporter.sendMail(mailOptions, function(err, info) {
        if (err) {
            console.log('error sending email to ' + mailOptions.to);
        }
        else {
            console.log('sent email to ' + mailOptions.to + ' (' + info.response + ')');
        }
    });
}
