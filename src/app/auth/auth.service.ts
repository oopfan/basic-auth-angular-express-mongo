import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';
import { tap } from 'rxjs/operators';

interface SignupCredentials {
  username: string;
  password: string;
  passwordConfirmation: string;
}

interface SigninCredentials {
  username: string;
  password: string;
}

interface SignupResponse {
  username: string;
}

interface SignedinResponse {
  authenticated: boolean;
  username: string;
}

export interface AuthStatus {
  signedIn: boolean;
  username: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  rootUrl = 'http://localhost:9000/api';
  authStatus$ = new BehaviorSubject<AuthStatus>({ signedIn: false, username: undefined });

  constructor(private http: HttpClient) { }

  usernameAvailable(username: string) {
    return this.http.post<{ available: boolean }>(this.rootUrl + '/auth/username', { username });
  }

  signup(credentials: SignupCredentials) {
    return this.http.post<SignupResponse>(this.rootUrl + '/auth/signup', credentials, { withCredentials: true })
      .pipe(tap((value) => { this.authStatus$.next({ signedIn: true, username: value.username }); }));
  }

  checkAuth() {
    return this.http.get<SignedinResponse>(this.rootUrl + '/auth/signedin', { withCredentials: true })
      .pipe(tap((value) => { this.authStatus$.next({ signedIn: value.authenticated, username: value.username }); }));
  }

  signout() {
    return this.http.post<any>(this.rootUrl + '/auth/signout', {}, { withCredentials: true })
      .pipe(tap(() => { this.authStatus$.next({ signedIn: false, username: undefined }); }));
  }

  signin(credentials: SigninCredentials) {
    return this.http.post<SigninCredentials>(this.rootUrl + '/auth/signin', credentials, { withCredentials: true })
      .pipe(tap((value) => { this.authStatus$.next({ signedIn: true, username: value.username }); }));
  }
}
