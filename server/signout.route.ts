import {Request, Response} from 'express';

export function signoutUser(req: Request, res: Response) {
    console.log("User signout attempt ...");
  
    const session = req['session'];
    session.username = undefined;
    res.status(200).json({});
}
