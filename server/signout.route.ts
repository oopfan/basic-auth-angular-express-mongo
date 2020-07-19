import {Request, Response} from 'express';

export function signoutUser(req: Request, res: Response) {
    console.log("User signout attempt ...");
  
    const username = req.cookies.user;

    if (username) {
      res.status(200).clearCookie('user', { sameSite: 'lax' }).json({});
    }
    else {
      res.status(200).json({});
    }
}
