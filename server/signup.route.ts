import {Request, Response} from 'express';
import {available, register} from "./db-data";

export function signupUser(req: Request, res: Response) {
  console.log("User signup attempt ...");

  const {username, password, passwordConfirmation} = req.body;

  if (available(username)) {
    const user = register(username, password, passwordConfirmation);
    if (user) {
      res.status(201).cookie('user', user.username, { sameSite: 'lax' }).json({username: user.username});
    }
    else {
      res.status(422).json({passwordConfirmation: 'Passwords must match'});
    }
  }
  else {
    res.status(422).json({username: 'Username in use'});
  }

}
