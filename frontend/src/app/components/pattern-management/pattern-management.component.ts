import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { PatternService, Pattern, PatternFile } from '../../services/pattern.service';
import { ScanService } from '../../services/scan.service';
import { Subscription } from 'rxjs';
import { trigger, transition, style, animate } from '@angular/animations';

@Component({
  selector: 'app-pattern-management',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './pattern-management.component.html',
  styleUrls: ['./pattern-management.component.css'],
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
export class PatternManagementComponent implements OnInit, OnDestroy {
  patternFiles: PatternFile[] = [];
  selectedFile: PatternFile | null = null;
  selectedPattern: Pattern | null = null;
  isLoading = false;
  error: string | null = null;
  success: string | null = null;
  
  // Modal states
  showAddPatternModal = false;
  showEditPatternModal = false;
  showTestPatternModal = false;
  showAddFileModal = false;
  
  // Form data
  newPattern: Pattern = {
    name: '',
    regex: '',
    confidence: 'high',
    enabled: true
  };
  
  testSampleText = '';
  testResults: { matched: boolean; matches: string[]; count: number } | null = null;
  
  newFileName = '';
  
  particlePositions: Array<{top: string, left: string, size: string, delay: string}> = [];
  private particleSubscription: Subscription | undefined;

  constructor(
    private patternService: PatternService,
    private scanService: ScanService
  ) {}

  ngOnInit() {
    this.loadPatterns();
    
    // Get particle positions for background
    this.particleSubscription = this.scanService.particlePositions$.subscribe(positions => {
      this.particlePositions = positions;
    });
  }

  ngOnDestroy() {
    if (this.particleSubscription) {
      this.particleSubscription.unsubscribe();
    }
  }

  loadPatterns() {
    this.isLoading = true;
    this.error = null;
    
    this.patternService.listPatterns().subscribe({
      next: (response) => {
        this.patternFiles = response.files;
        this.isLoading = false;
      },
      error: (err) => {
        this.error = err.error?.error || 'Failed to load patterns';
        this.isLoading = false;
      }
    });
  }

  selectFile(file: PatternFile) {
    this.selectedFile = file;
    this.selectedPattern = null;
  }

  selectPattern(pattern: Pattern) {
    this.selectedPattern = pattern;
  }

  openAddPatternModal() {
    this.newPattern = {
      name: '',
      regex: '',
      confidence: 'high',
      enabled: true
    };
    this.showAddPatternModal = true;
    this.error = null;
  }

  closeAddPatternModal() {
    this.showAddPatternModal = false;
    this.newPattern = {
      name: '',
      regex: '',
      confidence: 'high',
      enabled: true
    };
  }

  addPattern() {
    if (!this.selectedFile) {
      this.error = 'Please select a file first';
      return;
    }

    if (!this.newPattern.name || !this.newPattern.regex) {
      this.error = 'Name and regex are required';
      return;
    }

    this.isLoading = true;
    this.error = null;
    
    this.patternService.addPattern(this.selectedFile.filename, this.newPattern).subscribe({
      next: () => {
        this.success = 'Pattern added successfully';
        this.closeAddPatternModal();
        this.loadPatterns();
        // Reload selected file
        if (this.selectedFile) {
          this.patternService.getPatternFile(this.selectedFile.filename).subscribe({
            next: (file) => {
              this.selectedFile = { filename: file.filename, patterns: file.patterns };
            }
          });
        }
        setTimeout(() => this.success = null, 3000);
      },
      error: (err) => {
        this.error = err.error?.error || 'Failed to add pattern';
        this.isLoading = false;
      }
    });
  }

  openEditPatternModal(pattern: Pattern) {
    this.selectedPattern = { ...pattern };
    this.newPattern = { ...pattern };
    this.showEditPatternModal = true;
    this.error = null;
  }

  closeEditPatternModal() {
    this.showEditPatternModal = false;
    this.selectedPattern = null;
  }

  updatePattern() {
    if (!this.selectedFile || !this.selectedPattern) {
      this.error = 'Please select a file and pattern';
      return;
    }

    if (!this.newPattern.name || !this.newPattern.regex) {
      this.error = 'Name and regex are required';
      return;
    }

    this.isLoading = true;
    this.error = null;
    
    this.patternService.updatePattern(
      this.selectedFile.filename,
      this.selectedPattern.name,
      this.newPattern
    ).subscribe({
      next: () => {
        this.success = 'Pattern updated successfully';
        this.closeEditPatternModal();
        this.loadPatterns();
        // Reload selected file
        if (this.selectedFile) {
          this.patternService.getPatternFile(this.selectedFile.filename).subscribe({
            next: (file) => {
              this.selectedFile = { filename: file.filename, patterns: file.patterns };
            }
          });
        }
        setTimeout(() => this.success = null, 3000);
      },
      error: (err) => {
        this.error = err.error?.error || 'Failed to update pattern';
        this.isLoading = false;
      }
    });
  }

  deletePattern(pattern: Pattern) {
    if (!this.selectedFile) {
      this.error = 'Please select a file first';
      return;
    }

    if (!confirm(`Are you sure you want to delete pattern "${pattern.name}"?`)) {
      return;
    }

    this.isLoading = true;
    this.error = null;
    
    this.patternService.deletePattern(this.selectedFile.filename, pattern.name).subscribe({
      next: () => {
        this.success = 'Pattern deleted successfully';
        this.loadPatterns();
        // Reload selected file
        if (this.selectedFile) {
          this.patternService.getPatternFile(this.selectedFile.filename).subscribe({
            next: (file) => {
              this.selectedFile = { filename: file.filename, patterns: file.patterns };
            }
          });
        }
        setTimeout(() => this.success = null, 3000);
      },
      error: (err) => {
        this.error = err.error?.error || 'Failed to delete pattern';
        this.isLoading = false;
      }
    });
  }

  togglePattern(pattern: Pattern) {
    if (!this.selectedFile) {
      return;
    }

    this.patternService.enableDisablePattern(
      this.selectedFile.filename,
      pattern.name,
      !pattern.enabled
    ).subscribe({
      next: () => {
        pattern.enabled = !pattern.enabled;
        this.success = `Pattern ${pattern.enabled ? 'enabled' : 'disabled'} successfully`;
        setTimeout(() => this.success = null, 3000);
      },
      error: (err) => {
        this.error = err.error?.error || 'Failed to toggle pattern';
      }
    });
  }

  openTestPatternModal(pattern: Pattern) {
    this.selectedPattern = pattern;
    this.testSampleText = '';
    this.testResults = null;
    this.showTestPatternModal = true;
    this.error = null;
  }

  closeTestPatternModal() {
    this.showTestPatternModal = false;
    this.selectedPattern = null;
    this.testSampleText = '';
    this.testResults = null;
  }

  testPattern() {
    if (!this.selectedFile || !this.selectedPattern) {
      this.error = 'Please select a file and pattern';
      return;
    }

    if (!this.testSampleText.trim()) {
      this.error = 'Please enter sample text to test';
      return;
    }

    this.isLoading = true;
    this.error = null;
    
    this.patternService.testPattern(
      this.selectedFile.filename,
      this.selectedPattern.name,
      this.testSampleText
    ).subscribe({
      next: (results) => {
        this.testResults = results;
        this.isLoading = false;
      },
      error: (err) => {
        this.error = err.error?.error || 'Failed to test pattern';
        this.isLoading = false;
      }
    });
  }

  openAddFileModal() {
    this.newFileName = '';
    this.showAddFileModal = true;
    this.error = null;
  }

  closeAddFileModal() {
    this.showAddFileModal = false;
    this.newFileName = '';
  }

  createPatternFile() {
    if (!this.newFileName.trim()) {
      this.error = 'File name is required';
      return;
    }

    this.isLoading = true;
    this.error = null;
    
    this.patternService.createPatternFile(this.newFileName, []).subscribe({
      next: () => {
        this.success = 'Pattern file created successfully';
        this.closeAddFileModal();
        this.loadPatterns();
        setTimeout(() => this.success = null, 3000);
      },
      error: (err) => {
        this.error = err.error?.error || 'Failed to create pattern file';
        this.isLoading = false;
      }
    });
  }

  deleteFile(file: PatternFile) {
    if (!confirm(`Are you sure you want to delete file "${file.filename}"? This will delete all patterns in this file.`)) {
      return;
    }

    this.isLoading = true;
    this.error = null;
    
    this.patternService.deletePatternFile(file.filename).subscribe({
      next: () => {
        this.success = 'Pattern file deleted successfully';
        this.selectedFile = null;
        this.selectedPattern = null;
        this.loadPatterns();
        setTimeout(() => this.success = null, 3000);
      },
      error: (err) => {
        this.error = err.error?.error || 'Failed to delete pattern file';
        this.isLoading = false;
      }
    });
  }

  goBack() {
    this.scanService.setCurrentScreen('upload');
  }

  // trackBy fns: Angular re-renders only changed rows when these are used.
  trackByFilename = (_: number, f: PatternFile) => f.filename;
  trackByPatternName = (_: number, p: Pattern) => p.name;
}

