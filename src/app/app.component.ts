import { Component, OnInit } from '@angular/core';
import { Observable } from 'rxjs';
import { AuthService, AuthStatus } from './auth/auth.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  title = 'basic-auth-angular-express-mongo';
  authStatus$: Observable<AuthStatus>;

  constructor(public authService: AuthService) {
    this.authStatus$ = this.authService.authStatus$;
  }

  ngOnInit(): void {
    this.authService.checkAuth().subscribe(() => {});
  }

}
