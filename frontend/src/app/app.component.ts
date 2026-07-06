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
import { PatternManagementComponent } from './components/pattern-management/pattern-management.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule, 
    RouterOutlet,
    SplashScreenComponent,
    UploadScreenComponent,
    ProcessingScreenComponent,
    ResultsScreenComponent,
    PatternManagementComponent
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
  currentScreen: 'splash' | 'upload' | 'processing' | 'results' | 'patterns' = 'splash';
  // Latest scan error surfaced by ScanService (null when there is none). Rendered
  // as a dismissible banner instead of the old blocking alert() dialogs.
  scanError: string | null = null;
  private screenSubscription: Subscription | undefined;
  private errorSubscription: Subscription | undefined;

  constructor(private scanService: ScanService) {}

  ngOnInit() {
    // Subscribe to the current screen from the scan service
    this.screenSubscription = this.scanService.currentScreen$.subscribe(screen => {
      this.currentScreen = screen;
    });

    // Surface scan errors inline via a top-level banner.
    this.errorSubscription = this.scanService.scanError$.subscribe(error => {
      this.scanError = error;
    });
  }

  dismissError() {
    this.scanService.clearError();
  }

  ngOnDestroy() {
    // Clean up subscriptions
    if (this.screenSubscription) {
      this.screenSubscription.unsubscribe();
    }
    if (this.errorSubscription) {
      this.errorSubscription.unsubscribe();
    }
  }
}
