import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScanService } from '../../services/scan.service';
import { trigger, transition, style, animate } from '@angular/animations';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-upload-screen',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './upload-screen.component.html',
  styleUrls: ['./upload-screen.component.css'],
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
export class UploadScreenComponent implements OnInit, OnDestroy {
  selectedPlatform: 'android' | 'ios' = 'android';
  particlePositions: Array<{top: string, left: string, size: string, delay: string}> = [];
  matrixChars: string[] = [];
  
  private platformSubscription: Subscription | undefined;
  private particleSubscription: Subscription | undefined;
  private matrixInterval: any;
  
  // Characters to use for the Matrix effect
  private matrixCharPool: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+{}|:<>?';
  private originalText: string = 'SYSTEM READY';

  constructor(private scanService: ScanService) {}

  ngOnInit() {
    // Get particle positions from service
    this.particleSubscription = this.scanService.particlePositions$.subscribe(positions => {
      this.particlePositions = positions;
    });
    
    // Get selected platform from service
    this.platformSubscription = this.scanService.selectedPlatform$.subscribe(platform => {
      this.selectedPlatform = platform;
    });
    
    // Initialize matrix text effect
    this.initMatrixEffect();
  }

  ngOnDestroy() {
    // Clean up subscriptions and intervals
    if (this.particleSubscription) {
      this.particleSubscription.unsubscribe();
    }
    
    if (this.platformSubscription) {
      this.platformSubscription.unsubscribe();
    }
    
    if (this.matrixInterval) {
      clearInterval(this.matrixInterval);
    }
  }

  onDragOver(event: DragEvent) {
    event.preventDefault();
    event.stopPropagation();
  }

  onDrop(event: DragEvent) {
    event.preventDefault();
    event.stopPropagation();
    const files = event.dataTransfer?.files;
    if (files?.length) {
      this.handleFile(files[0]);
    }
  }

  onFileSelected(event: Event) {
    const input = event.target as HTMLInputElement;
    if (input.files?.length) {
      this.handleFile(input.files[0]);
    }
  }

  handleFile(file: File) {
    // Check if the file extension matches the selected platform
    const isAndroid = this.selectedPlatform === 'android';
    const expectedExt = isAndroid ? '.apk' : '.ipa';
    
    if (!file.name.toLowerCase().endsWith(expectedExt)) {
      alert(`Please select a${isAndroid ? 'n APK' : 'n IPA'} file for ${isAndroid ? 'Android' : 'iOS'} scanning`);
      return;
    }
    
    // Process the file using the scan service
    this.scanService.processFile(file);
  }

  setPlatform(platform: 'android' | 'ios') {
    this.scanService.setSelectedPlatform(platform);
  }

  initMatrixEffect() {
    // Initialize with random characters
    this.matrixChars = this.originalText.split('').map(() => 
      this.matrixCharPool.charAt(Math.floor(Math.random() * this.matrixCharPool.length))
    );
    
    // Phase 1: Initial scrambling
    const scrambleInterval = setInterval(() => {
      const newChars = [...this.matrixChars];
      for (let i = 0; i < newChars.length; i++) {
        if (Math.random() > 0.5) {
          newChars[i] = this.matrixCharPool.charAt(
            Math.floor(Math.random() * this.matrixCharPool.length)
          );
        }
      }
      this.matrixChars = newChars;
    }, 50);

    // Phase 2: Stabilize characters one by one
    setTimeout(() => {
      clearInterval(scrambleInterval);
      let index = 0;
      
      const stabilizeInterval = setInterval(() => {
        if (index >= this.originalText.length) {
          clearInterval(stabilizeInterval);
          this.startGlitchEffect();
          return;
        }
        
        const newChars = [...this.matrixChars];
        newChars[index] = this.originalText[index];
        this.matrixChars = newChars;
        index++;
      }, 100);
    }, 500);
  }

  startGlitchEffect() {
    // Phase 3: Occasional glitches
    this.matrixInterval = setInterval(() => {
      if (Math.random() > 0.8) {
        const glitchIndex = Math.floor(Math.random() * this.originalText.length);
        const glitchChar = this.matrixCharPool.charAt(
          Math.floor(Math.random() * this.matrixCharPool.length)
        );
        
        const glitchedChars = [...this.matrixChars];
        glitchedChars[glitchIndex] = glitchChar;
        this.matrixChars = glitchedChars;
        
        setTimeout(() => {
          const resetChars = [...this.matrixChars];
          resetChars[glitchIndex] = this.originalText[glitchIndex];
          this.matrixChars = resetChars;
        }, 100);
      }
    }, 300);
  }
}
