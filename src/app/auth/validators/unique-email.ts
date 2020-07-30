import { Injectable } from '@angular/core';
import { AsyncValidator, FormControl, AbstractControl } from '@angular/forms';
import { of } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import { AuthService } from '../auth.service';

@Injectable({ providedIn: 'root' })
export class UniqueEmail implements AsyncValidator {
    constructor(private authService: AuthService) {}

    // Arrow function needed in order to access 'this':
    validate = (control: FormControl) => {
        const { value } = control;
        return this.authService.emailAvailable(value).pipe(map(() => {
            return null;
        }), catchError(err => {
            if (err.error.email) {
                return of({ nonUniqueEmail: true });
            }
            else {
                return of({ noConnection: true });
            }
        }));
    }
}
