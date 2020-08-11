import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { AuthService } from './auth.service';
import { Observable } from 'rxjs';
import { pluck, skipWhile, take } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class UserActivatedGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> {
    return this.authService.authStatus$.pipe(skipWhile(value => value === null), take(1), pluck('activated'));
  }

}
