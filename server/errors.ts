import { Response } from 'express';

export const ErrorUsernameInUse = 'ErrorUsernameInUse';
export const ErrorUsernameNotFoundPasswordInvalid = 'ErrorUsernameNotFoundPasswordInvalid';
export const ErrorEmailInUse = 'ErrorEmailInUse';
export const ErrorUsernameFoundPasswordInvalid = 'ErrorUsernameFoundPasswordInvalid';
export const ErrorAccessingUserDatabase = 'ErrorAccessingUserDatabase';
export const ErrorCreatingToken = 'ErrorCreatingToken';
export const ErrorInvalidToken = 'ErrorInvalidToken';
export const ErrorExpiredToken = 'ErrorExpiredToken';
export const ErrorInvalidIPAddress = 'ErrorInvalidIPAddress';
export const ErrorCannotChangePasswordForAnotherUser = 'ErrorCannotChangePasswordForAnotherUser';
export const ErrorUnableToVerifyEmail = 'ErrorUnableToVerifyEmail';
export const ErrorSendingEmail = 'ErrorSendingEmail';

export function sendResponse(res: Response, errorCode: string) {
    // console.error(errorCode);
    switch (errorCode) {
        case ErrorUsernameInUse:
            return res.status(422).json({ username: 'Username in use' });
        case ErrorUsernameNotFoundPasswordInvalid:
            return res.status(422).json({ username: 'Username not found', password: 'Invalid password' });
        case ErrorEmailInUse:
            return res.status(422).json({ email: 'Email in use' });
        case ErrorUsernameFoundPasswordInvalid:
            return res.status(422).json({ username: 'Username or email already exists', password: 'Invalid password' });
        case ErrorAccessingUserDatabase:
            return res.status(500).json({ message: 'Error accessing user database' });
        case ErrorCreatingToken:
            return res.status(500).json({ message: 'Error creating token' });
        case ErrorInvalidToken:
            return res.status(403).json({ message: 'Invalid token' });
        case ErrorExpiredToken:
            return res.status(403).json({ message: 'Expired token' });
        case ErrorInvalidIPAddress:
            return res.status(403).json({ message: 'Invalid IP address' });
        case ErrorCannotChangePasswordForAnotherUser:
            return res.status(422).json({ message: 'Cannot change password for another user' });
        case ErrorUnableToVerifyEmail:
            return res.status(422).json({ message: 'Authentication failed, unable to verify email' });
        case ErrorSendingEmail:
            return res.status(400).json({ message: 'Error sending email' });
    }
}
