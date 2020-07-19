import {Request, Response} from 'express';

export function signedinUser(req: Request, res: Response) {
    console.log("User signedin attempt ...");
  
    const username = req.cookies.user;

    if (username) {
      res.status(200).json({authenticated: true, username});
    }
    else {
      res.status(200).json({authenticated: false, username: null});
    }
}
