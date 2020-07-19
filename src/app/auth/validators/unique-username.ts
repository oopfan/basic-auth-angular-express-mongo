import { Injectable } from '@angular/core';
import { AsyncValidator, FormControl } from '@angular/forms';
import { of } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import { AuthService } from '../auth.service';

@Injectable({ providedIn: 'root' })
export class UniqueUsername implements AsyncValidator {
    constructor(private authService: AuthService) {}

    // Arrow function needed in order to access 'this':
    validate = (control: FormControl) => {
        const { value } = control;
        return this.authService.usernameAvailable(value).pipe(map(() => {
            return null;
        }), catchError(err => {
            if (err.error.username) {
                return of({ nonUniqueUsername: true });
            }
            else {
                return of({ noConnection: true });
            }
        }));
    }
}
