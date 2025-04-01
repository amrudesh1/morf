import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScanService } from '../../services/scan.service';
import { trigger, transition, style, animate } from '@angular/animations';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-splash-screen',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './splash-screen.component.html',
  styleUrls: ['./splash-screen.component.css'],
  animations: [
    trigger('fadeInOut', [
      transition(':enter', [
        style({ opacity: 0 }),
        animate('300ms', style({ opacity: 1 }))
      ]),
      transition(':leave', [
        animate('300ms', style({ opacity: 0 }))
      ])
    ])
  ]
})
export class SplashScreenComponent implements OnInit, OnDestroy {
  particlePositions: Array<{top: string, left: string, size: string, delay: string}> = [];
  private particleSubscription: Subscription | undefined;
  
  // Matrix text effect properties
  matrixText: string = 'SYSTEM READY';
  matrixChars: string[] = [];
  frameworkMatrixChars: string[] = [];
  
  // Characters to use for the Matrix effect
  private matrixCharPool: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+{}|:<>?';
  private originalText: string = 'SYSTEM READY';
  private frameworkText: string = 'MOBILE RECONNAISSANCE FRAMEWORK';
  private matrixInterval: any;
  private frameworkMatrixInterval: any;

  constructor(private scanService: ScanService) {}

  ngOnInit() {
    // Get particle positions from service
    this.particleSubscription = this.scanService.particlePositions$.subscribe(positions => {
      this.particlePositions = positions;
    });
    
    // Initialize matrix text effects
    this.initMatrixEffect();
    this.initFrameworkMatrixEffect();
    
    // Reduced splash screen time from 8 to 5 seconds
    setTimeout(() => {
      // Clear the matrix intervals when transitioning away from splash screen
      if (this.matrixInterval) {
        clearInterval(this.matrixInterval);
      }
      if (this.frameworkMatrixInterval) {
        clearInterval(this.frameworkMatrixInterval);
      }
      this.scanService.setCurrentScreen('upload');
    }, 5000);
  }

  ngOnDestroy() {
    // Clean up subscriptions and intervals
    if (this.particleSubscription) {
      this.particleSubscription.unsubscribe();
    }
    
    if (this.matrixInterval) {
      clearInterval(this.matrixInterval);
    }
    
    if (this.frameworkMatrixInterval) {
      clearInterval(this.frameworkMatrixInterval);
    }
  }

  initMatrixEffect() {
    // Initialize the matrix characters array with random characters
    this.matrixChars = this.originalText.split('').map(() => 
      this.matrixCharPool.charAt(Math.floor(Math.random() * this.matrixCharPool.length))
    );
    
    // Phase 1: Initial scrambling (0-2s)
    // Completely random characters that change rapidly
    const scrambleDuration = 1000; // Reduced from 2000ms to 1000ms
    this.matrixInterval = setInterval(() => {
      const newChars = [...this.matrixChars];
      for (let i = 0; i < newChars.length; i++) {
        if (Math.random() > 0.7) { // Reduced frequency of changes
          newChars[i] = this.matrixCharPool.charAt(
            Math.floor(Math.random() * this.matrixCharPool.length)
          );
        }
      }
      this.matrixChars = newChars;
    }, 50); // Reduced interval from 100ms to 50ms for smoother animation
    
    // Phase 2: Character stabilization (2-5s)
    // Characters stabilize one by one from left to right
    setTimeout(() => {
      clearInterval(this.matrixInterval);
      
      const stabilizationDuration = 1500; // Reduced from 3000ms to 1500ms
      const totalChars = this.originalText.length;
      const timePerChar = stabilizationDuration / totalChars;
      
      // Set up a new interval that will continue scrambling unstabilized characters
      this.matrixInterval = setInterval(() => {
        // This will be updated as characters stabilize
      }, 100);
      
      // Stabilize one character at a time
      let stabilizedChars = 0;
      const stabilizeNextChar = () => {
        if (stabilizedChars >= totalChars) {
          clearInterval(this.matrixInterval);
          this.startGlitchEffect();
          return;
        }
        
        // Update the current character to its final state
        const updatedChars = [...this.matrixChars];
        updatedChars[stabilizedChars] = this.originalText[stabilizedChars];
        this.matrixChars = updatedChars;
        
        // Update the scrambling interval to leave stabilized characters alone
        clearInterval(this.matrixInterval);
        this.matrixInterval = setInterval(() => {
          const currentChars = [...this.matrixChars];
          for (let i = stabilizedChars + 1; i < totalChars; i++) {
            if (Math.random() > 0.5) {
              currentChars[i] = this.matrixCharPool.charAt(
                Math.floor(Math.random() * this.matrixCharPool.length)
              );
            }
          }
          this.matrixChars = currentChars;
        }, 100);
        
        stabilizedChars++;
        setTimeout(stabilizeNextChar, timePerChar);
      };
      
      // Start the stabilization process
      stabilizeNextChar();
    }, scrambleDuration);
  }
  
  // Phase 3: Occasional glitches (5-8s)
  // Text is fully formed but with occasional random glitches
  startGlitchEffect() {
    // Ensure we start with the correct text
    this.matrixChars = this.originalText.split('');
    
    // Add occasional glitches
    this.matrixInterval = setInterval(() => {
      if (Math.random() > 0.7) {
        const glitchIndex = Math.floor(Math.random() * this.originalText.length);
        const glitchChar = this.matrixCharPool.charAt(
          Math.floor(Math.random() * this.matrixCharPool.length)
        );
        
        // Create a temporary glitch
        const glitchedChars = [...this.matrixChars];
        glitchedChars[glitchIndex] = glitchChar;
        this.matrixChars = glitchedChars;
        
        // Reset back to original after a short delay
        setTimeout(() => {
          const resetChars = [...this.matrixChars];
          resetChars[glitchIndex] = this.originalText[glitchIndex];
          this.matrixChars = resetChars;
        }, 150);
      }
    }, 500);
  }
  
  // Initialize the matrix effect for the framework text
  initFrameworkMatrixEffect() {
    // Initialize the framework matrix characters array with random characters
    this.frameworkMatrixChars = this.frameworkText.split('').map(() => 
      this.matrixCharPool.charAt(Math.floor(Math.random() * this.matrixCharPool.length))
    );
    
    // Phase 1: Initial scrambling (0-2s)
    // Completely random characters that change rapidly
    const scrambleDuration = 1000; // Reduced from 2000ms to 1000ms
    this.frameworkMatrixInterval = setInterval(() => {
      const newChars = [...this.frameworkMatrixChars];
      for (let i = 0; i < newChars.length; i++) {
        if (Math.random() > 0.7) { // Reduced frequency of changes
          newChars[i] = this.matrixCharPool.charAt(
            Math.floor(Math.random() * this.matrixCharPool.length)
          );
        }
      }
      this.frameworkMatrixChars = newChars;
    }, 50); // Reduced interval from 100ms to 50ms for smoother animation
    
    // Phase 2: Character stabilization (2-5s)
    // Characters stabilize one by one from left to right
    setTimeout(() => {
      clearInterval(this.frameworkMatrixInterval);
      
      const stabilizationDuration = 1500; // Reduced from 3000ms to 1500ms
      const totalChars = this.frameworkText.length;
      const timePerChar = stabilizationDuration / totalChars;
      
      // Set up a new interval that will continue scrambling unstabilized characters
      this.frameworkMatrixInterval = setInterval(() => {
        // This will be updated as characters stabilize
      }, 100);
      
      // Stabilize one character at a time
      let stabilizedChars = 0;
      const stabilizeNextChar = () => {
        if (stabilizedChars >= totalChars) {
          clearInterval(this.frameworkMatrixInterval);
          this.startFrameworkGlitchEffect();
          return;
        }
        
        // Update the current character to its final state
        const updatedChars = [...this.frameworkMatrixChars];
        updatedChars[stabilizedChars] = this.frameworkText[stabilizedChars];
        this.frameworkMatrixChars = updatedChars;
        
        // Update the scrambling interval to leave stabilized characters alone
        clearInterval(this.frameworkMatrixInterval);
        this.frameworkMatrixInterval = setInterval(() => {
          const currentChars = [...this.frameworkMatrixChars];
          for (let i = stabilizedChars + 1; i < totalChars; i++) {
            if (Math.random() > 0.5) {
              currentChars[i] = this.matrixCharPool.charAt(
                Math.floor(Math.random() * this.matrixCharPool.length)
              );
            }
          }
          this.frameworkMatrixChars = currentChars;
        }, 100);
        
        stabilizedChars++;
        setTimeout(stabilizeNextChar, timePerChar);
      };
      
      // Start the stabilization process
      stabilizeNextChar();
    }, scrambleDuration);
  }
  
  // Phase 3: Final bold transition effect for framework text
  startFrameworkGlitchEffect() {
    // Set the final text
    this.frameworkMatrixChars = this.frameworkText.split('');
    
    // Add class to trigger bold transition
    setTimeout(() => {
      const element = document.querySelector('.framework-text');
      if (element) {
        element.classList.add('text-bold-transition');
      }
    }, 100);
  }
}
