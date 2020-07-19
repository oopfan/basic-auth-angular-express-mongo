import {Request, Response} from 'express';
import {available, authenticate} from "./db-data";

export function signinUser(req: Request, res: Response) {
  console.log("User signin attempt ...");

  const {username, password} = req.body;

  const user = authenticate(username, password);
  if (user) {
    res.status(200).cookie('user', user.username, { sameSite: 'lax' }).json({username: user.username});
  }
  else {
    res.status(422).json({username: 'Username not found', password: 'Invalid password'});
  }
}
