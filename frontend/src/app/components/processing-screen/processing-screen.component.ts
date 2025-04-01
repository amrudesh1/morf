import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScanService } from '../../services/scan.service';
import { trigger, transition, style, animate } from '@angular/animations';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-processing-screen',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './processing-screen.component.html',
  styleUrls: ['./processing-screen.component.css'],
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
export class ProcessingScreenComponent implements OnInit, OnDestroy {
  selectedPlatform: 'android' | 'ios' = 'android';
  currentFile: File | null = null;
  particlePositions: Array<{top: string, left: string, size: string, delay: string}> = [];
  
  private platformSubscription: Subscription | undefined;
  private fileSubscription: Subscription | undefined;
  private particleSubscription: Subscription | undefined;

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
    
    // Get current file from service
    this.fileSubscription = this.scanService.currentFile$.subscribe(file => {
      this.currentFile = file;
    });
  }

  ngOnDestroy() {
    // Clean up subscriptions
    if (this.particleSubscription) {
      this.particleSubscription.unsubscribe();
    }
    
    if (this.platformSubscription) {
      this.platformSubscription.unsubscribe();
    }
    
    if (this.fileSubscription) {
      this.fileSubscription.unsubscribe();
    }
  }

  getFileSize(): string {
    if (!this.currentFile) return 'Unknown size';
    return (this.currentFile.size / 1024 / 1024).toFixed(2) + ' MB';
  }
}
