import {Request, Response} from 'express';
import * as mongoose from 'mongoose';
import { Config } from './config';

mongoose.connect(Config.MONGO_CONNECT, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
});


interface IUser extends mongoose.Document {
    username: string,
    password: string
}

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const UserModel = mongoose.model<IUser>('User', UserSchema);


export function availableUser(req: Request, res: Response) {
    console.log("User available attempt ...");
  
    const {username} = req.body;
    const searchUser = { username };

    UserModel.findOne(searchUser, function(err, user) {
        if (!err && !user) {
            res.status(200).json({available: true});
        }
        else {
            res.status(422).json({username: 'Username in use'});
        }
    });
}

export function signedinUser(req: Request, res: Response) {
    console.log("User signedin attempt ...");
  
    const session = req['session'];
    const username = session.username;

    if (username) {
        res.status(200).json({authenticated: true, username});
    }
    else {
        res.status(200).json({authenticated: false, username: null});
    }
}

export function signinUser(req: Request, res: Response) {
    console.log("User signin attempt ...");
  
    const {username, password} = req.body;
    const searchUser = { username };
  
    UserModel.findOne(searchUser, function(err, user) {
        if (!err && user && user.password == password) {
            const session = req['session'];
            session.username = username;
            res.status(200).json({username});
        }
        else {
            res.status(422).json({username: 'Username not found', password: 'Invalid password'});
        }
    });

}
  
export function signoutUser(req: Request, res: Response) {
    console.log("User signout attempt ...");
  
    const session = req['session'];
    session.username = undefined;
    res.status(200).json({});
}

export function signupUser(req: Request, res: Response) {
    console.log("User signup attempt ...");
  
    const {username, password, passwordConfirmation} = req.body;
    const searchUser = { username };

    UserModel.findOne(searchUser, function(err, user) {
        if (!err && !user && password == passwordConfirmation) {
            const newUser = new UserModel({
                username,
                password
            });
            newUser.save(function(err) {
                if (!err) {
                    const session = req['session'];
                    session.username = username;
                    res.status(201).json({username});
                }
                else {
                    res.status(422).json({username: 'Username already exists', password: 'Invalid password'});
                }
            });
        }
        else {
            res.status(422).json({username: 'Username already exists', password: 'Invalid password'});
        }
    });

}
