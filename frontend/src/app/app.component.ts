import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';
import { ScanService } from './services/scan.service';
import { Subscription } from 'rxjs';
import { trigger, transition, style, animate, query, group } from '@angular/animations';

// Import the screen components
import { SplashScreenComponent } from './components/splash-screen/splash-screen.component';
import { UploadScreenComponent } from './components/upload-screen/upload-screen.component';
import { ProcessingScreenComponent } from './components/processing-screen/processing-screen.component';
import { ResultsScreenComponent } from './components/results-screen/results-screen.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule, 
    RouterOutlet,
    SplashScreenComponent,
    UploadScreenComponent,
    ProcessingScreenComponent,
    ResultsScreenComponent
  ],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'],
  animations: [
    trigger('screenAnimation', [
      transition('* => *', [
        group([
          query(':enter', [
            style({ 
              position: 'absolute',
              left: 0,
              right: 0,
              opacity: 0,
              transform: 'translateX(100%)' 
            }),
            animate('300ms ease-out', 
              style({ 
                opacity: 1,
                transform: 'translateX(0)' 
              })
            )
          ], { optional: true }),
          query(':leave', [
            style({ 
              position: 'absolute',
              left: 0,
              right: 0
            }),
            animate('300ms ease-out', 
              style({ 
                opacity: 0,
                transform: 'translateX(-100%)' 
              })
            )
          ], { optional: true })
        ])
      ])
    ])
  ]
})
export class AppComponent implements OnInit, OnDestroy {
  currentScreen: 'splash' | 'upload' | 'processing' | 'results' = 'splash';
  private screenSubscription: Subscription | undefined;
  
  constructor(private scanService: ScanService) {}
  
  ngOnInit() {
    // Subscribe to the current screen from the scan service
    this.screenSubscription = this.scanService.currentScreen$.subscribe(screen => {
      this.currentScreen = screen;
    });
  }
  
  ngOnDestroy() {
    // Clean up subscription
    if (this.screenSubscription) {
      this.screenSubscription.unsubscribe();
    }
  }
}
