import {Request, Response} from 'express';
import {available, authenticate} from "./db-data";

export function signinUser(req: Request, res: Response) {
  console.log("User signin attempt ...");

  const {username, password} = req.body;

  const user = authenticate(username, password);
  if (user) {
    const session = req['session'];
    session.username = username;
    res.status(200).json({username});
  }
  else {
    res.status(422).json({username: 'Username not found', password: 'Invalid password'});
  }
}
