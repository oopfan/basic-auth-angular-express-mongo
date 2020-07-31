import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

@Component({
  selector: 'app-welcome',
  templateUrl: './welcome.component.html',
  styleUrls: ['./welcome.component.css']
})
export class WelcomeComponent implements OnInit {
    id: string;

    constructor(private activatedRoute: ActivatedRoute, private router: Router) { }

    ngOnInit(): void {
        this.id = this.activatedRoute.snapshot.paramMap.get('id');
        if (this.id !== '1' && this.id !== '2') {
            this.router.navigate([ '/not-found' ]);
        }
    }

}
