import {Request, Response} from 'express';
import {available} from "./db-data";

export function availableUser(req: Request, res: Response) {
    console.log("User available attempt ...");
  
    const {username} = req.body;

    if (available(username)) {
      res.status(200).json({available: true});
    }
    else {
      res.status(422).json({username: 'Username in use'});
    }
}
