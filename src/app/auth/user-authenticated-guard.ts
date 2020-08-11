import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import { AuthService } from './auth.service';
import { Observable } from 'rxjs';
import { take, skipWhile, pluck, tap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class UserAuthenticatedGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> {
    return this.authService.authStatus$.pipe(skipWhile(value => value === null), take(1), pluck('authenticated'), tap(authenticated => {
      if (!authenticated) {
        this.router.navigateByUrl('/');
      }
    }));
  }

}
