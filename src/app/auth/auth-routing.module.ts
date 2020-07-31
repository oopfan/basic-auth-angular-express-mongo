import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { SigninComponent } from './signin/signin.component';
import { SignupComponent } from './signup/signup.component';
import { SignoutComponent } from './signout/signout.component';
import { WelcomeComponent } from './welcome/welcome.component';
import { UserAuthenticatedGuard } from './user-authenticated-guard';

const routes: Routes = [
  { path: 'signout', component: SignoutComponent, canActivate: [ UserAuthenticatedGuard ] },
  { path: 'signup', component: SignupComponent },
  { path: 'signin', component: SigninComponent },
  { path: 'welcome/:id', component: WelcomeComponent }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class AuthRoutingModule { }
