import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, of, Observable, throwError, iif } from 'rxjs';
import { tap, pluck, concatMap, catchError } from 'rxjs/operators';
import { LocalStorageService } from 'angular-web-storage';

interface SignupCredentials {
  username: string;
  password: string;
  passwordConfirmation: string;
}

interface SigninCredentials {
  username: string;
  password: string;
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
  private API_URL = 'http://localhost:9000/api/';  // Development
  authStatus$ = new BehaviorSubject<AuthStatus>({ signedIn: false, username: '' });
  private accessToken: string = null;

  constructor(private http: HttpClient, private storage: LocalStorageService) {}

  usernameAvailable(username: string) {
    return this.http.post<{ available: boolean }>(this.API_URL + 'auth/username', { username });
  }

  emailAvailable(email: string) {
    return this.http.post<{ available: boolean }>(this.API_URL + 'auth/email', { email });
  }

  signup(credentials: SignupCredentials) {
    return this.http.post<{ message: string}>(this.API_URL + 'auth/signup', credentials);
  }

  signin(credentials: SigninCredentials) {
    return this.http.post<{ _t: string}>(this.API_URL + 'auth/signin', credentials).pipe(
      pluck('_t'),
      tap(value => {
        this.storage.set('_t', value);
        this.authStatus$.next({ signedIn: true, username: credentials.username });
      })
    );
  }

  signout() {
    return this._protect(this._signout).pipe(
      catchError(() => {
        const value = { authenticated: false, username: '' };
        return of(value);
      }),
      tap(value => {
        this.authStatus$.next({ signedIn: value.authenticated, username: value.username });
        this.accessToken = null;
        this.storage.remove('_t');
      })
    );
  }

  checkAuth() {
    return this._protect(this._signedin).pipe(
      catchError(() => {
        const value = { authenticated: false, username: '' };
        return of(value);
      }),
      tap(value => {
        this.authStatus$.next({ signedIn: value.authenticated, username: value.username });
      })
    );
  }

  private _signedin = (accessToken: string): Observable<any> => {
    const headers = new HttpHeaders()
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Bearer ' + accessToken);
    return this.http.post<SignedinResponse>(this.API_URL + 'auth/signedin', {}, { headers });
  }

  private _signout = (accessToken: string) => {
    const headers = new HttpHeaders()
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Bearer ' + accessToken);
    return this.http.post<any>(this.API_URL + 'auth/signout', {}, { headers });
  }

  private _protect(resource: {(accessToken: string): Observable<any>}) : Observable<any> {
    const accessToken = this.accessToken;
    const refreshToken: string = this.storage.get('_t');

    const path1$ = iif(
      () => accessToken != null,
      of(accessToken).pipe(concatMap(resource)),
      throwError({error: {message: 'Access Token is null'}})
    );
  
    const path2$ = iif(
      () => refreshToken != null,
      this._createAccessToken(refreshToken).pipe(pluck('_t'), tap(value => { this.accessToken = value; }), concatMap(resource)),
      throwError({error: {message: 'Refresh Token is null'}})
    );

    return path1$.pipe(catchError(() => path2$));
  }

  private _createAccessToken(refreshToken: string) {
    const headers = new HttpHeaders()
      .set('Content-Type', 'application/json')
      .set('Authorization', 'Bearer ' + refreshToken);
    return this.http.post<{ _t: string}>(this.API_URL + 'auth/access', {}, { headers });
  }

}
