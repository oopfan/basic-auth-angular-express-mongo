import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, of, Observable, throwError, iif } from 'rxjs';
import { tap, concatMap, catchError } from 'rxjs/operators';
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

interface SigninResponse {
  accessToken: string;
  activated: boolean;
  username: string;
  isAdmin: boolean;
}

interface SignedinResponse {
  authenticated: boolean;
  activated: boolean;
  username: string;
  isAdmin: boolean;
}

export interface AuthStatus {
  authenticated: boolean;
  activated: boolean;
  username: string;
  isAdmin: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private API_URL = 'http://localhost:9000/api/';  // Development
  authStatus$ = new BehaviorSubject<AuthStatus>(null);

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
    return this.http.post<SigninResponse>(this.API_URL + 'auth/signin', credentials).pipe(
      tap(value => {
        this.storage.set('_t', value.accessToken);
        this.authStatus$.next({ authenticated: true, activated: value.activated, username: value.username, isAdmin: value.isAdmin });
      })
    );
  }

  signout() {
    return this._protect(this._signout).pipe(
      catchError(() => {
        return of({});
      }),
      tap(() => {
        this.authStatus$.next({ authenticated: false, activated: false, username: '', isAdmin: false });
        this.storage.remove('_t');
      })
    );
  }

  checkAuth() {
    return this._protect<SignedinResponse>(this._signedin).pipe(
      catchError(() => {
        const value = { authenticated: false, activated: false, username: '', isAdmin: false };
        return of(value);
      }),
      tap(value => {
        this.authStatus$.next({ authenticated: value.authenticated, activated: value.activated, username: value.username, isAdmin: value.isAdmin });
      })
    );
  }

  private _signedin = (accessToken: string): Observable<SignedinResponse> => {
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

  private _protect<T>(resource: {(accessToken: string): Observable<T>}) : Observable<T> {
    const accessToken: string = this.storage.get('_t');

    const path1$ = iif(
      () => accessToken != null,
      of(accessToken).pipe(concatMap(resource)),
      throwError({error: {message: 'Access Token is null'}})
    );
  
    return path1$;
  }

}
