import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { MatchPassword } from '../validators/match-password';
import { UniqueUsername } from '../validators/unique-username';
import { UniqueEmail } from '../validators/unique-email';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-signup',
  templateUrl: './signup.component.html',
  styleUrls: ['./signup.component.css']
})
export class SignupComponent implements OnInit {
  authForm = new FormGroup({
    username: new FormControl('', [
      Validators.required,
      Validators.minLength(3),
      Validators.maxLength(20),
      Validators.pattern(/^[a-z0-9]+$/)
    ], [ this.uniqueUsername.validate ]),
    email: new FormControl('', [
      Validators.required,
      Validators.email
    ], [ this.uniqueEmail.validate ]),
    password: new FormControl('', [
      Validators.required,
      Validators.minLength(4),
      Validators.maxLength(20)
    ]),
    passwordConfirmation: new FormControl('', [
      Validators.required,
      Validators.minLength(4),
      Validators.maxLength(20)
    ])
  }, { validators: [ this.matchPassword.validate ] });

  constructor(
    private matchPassword: MatchPassword,
    private uniqueUsername: UniqueUsername,
    private uniqueEmail: UniqueEmail,
    private authService: AuthService,
    private router: Router
    ) { }

  ngOnInit(): void {
  }

  onSubmit() {
    if (this.authForm.invalid) {
      return;
    }
    this.authService.signup(this.authForm.value).subscribe({
      // Arrow functions used so that we can gain access to 'this':
      next: response => {
        this.router.navigateByUrl('/welcome/1');
      },
      error: err => {
        if (!err.status) {
          this.authForm.setErrors({ noConnection: true });
        }
        else {
          this.authForm.setErrors({ unknownError: true });
        }
      }
    });
  }
}
