import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, catchError, finalize, Observable, Observer, of } from 'rxjs';

// Backend secret format
interface BackendSecret {
  type: string;
  lineNo: number;
  secretType: string;
  fileLocation: string;
  secretString: string;
  secretConfidence: 'high' | 'low';
}

// Frontend format matches backend format for simplicity
export interface Secret {
  type: string;
  lineNo: number;
  secretType: string;
  fileLocation: string;
  secretString: string;
  secretConfidence: 'high' | 'low';
}

interface ScanResponse {
  message: string;
  data: {
    fileName: string;
    packageName: string;
    version: string;
    minSdk: string;
    targetSdk: string;
    permissions: string[];
    secretCount: number;
    secrets: BackendSecret[];
    createdAt: string;
    // New fields
    activities: Array<{
      name: string;
      exported: boolean;
      intentFilters: Array<{
        actions: string[];
        data: Array<{
          scheme: string;
          host: string;
          path: string;
          pathPrefix: string[];
          pathPattern: string;
          port: string;
          mimeType: string;
        }>;
        priority: number;
      }>;
    }>;
    services: Array<{
      name: string;
      exported: boolean;
    }>;
    contentProviders: Array<{
      name: string;
      exported: boolean;
    }>;
    broadcastReceivers: Array<{
      name: string;
      exported: boolean;
    }>;
    usesLibrary: string[];
    customPermissions: string[];
    usesFeatures: string[];
    resourceData: {
      numberOfStringResource: number;
      drawables: {
        png: number;
        jpg: number;
        gif: number;
        xml: number;
      };
      layouts: number;
    };
  };
}

@Injectable({
  providedIn: 'root'
})
export class ScanService {
  // API URL - use relative URL to go through nginx proxy
  private apiUrl = '/api';

  // Platform selection
  private selectedPlatformSubject = new BehaviorSubject<'android' | 'ios'>('android');
  selectedPlatform$ = this.selectedPlatformSubject.asObservable();

  // Current file
  private currentFileSubject = new BehaviorSubject<File | null>(null);
  currentFile$ = this.currentFileSubject.asObservable();

  // Scan results
  private secretsSubject = new BehaviorSubject<Secret[]>([]);
  secrets$ = this.secretsSubject.asObservable();

  // Package metadata
  private metadataSubject = new BehaviorSubject<{
    packageName: string;
    version: string;
    minSdk: string;
    targetSdk: string;
    permissions: string[];
    activities: Array<{
      name: string;
      exported: boolean;
      intentFilters: Array<{
        actions: string[];
        data: Array<{
          scheme: string;
          host: string;
          path: string;
          pathPrefix: string[];
          pathPattern: string;
          port: string;
          mimeType: string;
        }>;
        priority: number;
      }>;
    }>;
    services: Array<{
      name: string;
      exported: boolean;
    }>;
    contentProviders: Array<{
      name: string;
      exported: boolean;
    }>;
    broadcastReceivers: Array<{
      name: string;
      exported: boolean;
    }>;
    usesLibrary: string[];
    customPermissions: string[];
    usesFeatures: string[];
    resourceData: {
      numberOfStringResource: number;
      drawables: {
        png: number;
        jpg: number;
        gif: number;
        xml: number;
      };
      layouts: number;
    };
  } | null>(null);
  metadata$ = this.metadataSubject.asObservable();

  // Current screen
  private currentScreenSubject = new BehaviorSubject<'splash' | 'upload' | 'processing' | 'results'>('splash');
  currentScreen$ = this.currentScreenSubject.asObservable();

  // Particle positions for background animation
  private particlePositionsSubject = new BehaviorSubject<Array<{top: string, left: string, size: string, delay: string}>>([]);
  particlePositions$ = this.particlePositionsSubject.asObservable();

  constructor(private http: HttpClient) {
    this.generateParticlePositions();
  }

  setSelectedPlatform(platform: 'android' | 'ios') {
    this.selectedPlatformSubject.next(platform);
  }

  setCurrentFile(file: File | null) {
    this.currentFileSubject.next(file);
  }

  setSecrets(secrets: Secret[]) {
    this.secretsSubject.next(secrets);
  }

  setCurrentScreen(screen: 'splash' | 'upload' | 'processing' | 'results') {
    this.currentScreenSubject.next(screen);
  }

  getCurrentScreen() {
    return this.currentScreenSubject.getValue();
  }

  resetScan() {
    this.currentFileSubject.next(null);
    this.secretsSubject.next([]);
    this.metadataSubject.next(null);
    this.setCurrentScreen('upload');
  }

  processFile(file: File) {
    console.log('Processing file:', file.name);
    this.currentFileSubject.next(file);
    this.setCurrentScreen('processing');
    
    // Upload and scan the file
    const formData = new FormData();
    formData.append('file', file);
    
    console.log('Making API request to:', `${this.apiUrl}/upload`);
    this.http.post<{message: string}>(`${this.apiUrl}/upload`, formData)
      .pipe(
        catchError(error => {
          console.error('Error uploading file:', error);
          let errorMessage = 'Error uploading file. Please try again.';
          
          if (error.error instanceof Blob) {
            // Return a new Observable for Blob error handling
            return new Observable<{message: string}>((observer: Observer<{message: string}>) => {
              const reader = new FileReader();
              reader.onload = () => {
                try {
                  const errorResponse = JSON.parse(reader.result as string);
                  errorMessage = errorResponse.error || errorMessage;
                } catch (e) {
                  console.error('Error parsing error response:', e);
                }
                this.resetScan();
                alert(errorMessage);
                observer.error(error);
              };
              reader.readAsText(error.error);
            });
          } else if (error.error?.error) {
            errorMessage = error.error.error;
          }
          
          this.resetScan();
          alert(errorMessage);
          return of({ message: errorMessage }); // Return an Observable
        })
      )
      .subscribe({
        next: (response) => {
          console.log('Upload Response:', response);
          // Start polling for results
          this.pollForResults(file.name);
        },
        error: (error) => {
          // Error is already handled in catchError
          console.error('Upload error:', error);
        }
      });
  }

  private pollForResults(fileName: string) {
    console.log('Starting to poll for results:', fileName);
    const pollInterval = setInterval(() => {
      console.log('Polling API for results...');
      this.http.get<ScanResponse>(`${this.apiUrl}/results/${fileName}`)
        .subscribe({
          next: (response) => {
            console.log('Received API response:', response);
            if (response && response.data) {
              console.log('Valid response data received');
              // Clear polling
              clearInterval(pollInterval);
              
              // Set secrets
              if (response.data.secrets) {
                console.log('Setting secrets:', response.data.secrets.length);
                // Transform backend secrets to frontend format
                const transformedSecrets = response.data.secrets.map((secret: BackendSecret) => ({
                  type: secret.type,
                  lineNo: secret.lineNo,
                  secretType: secret.secretType,
                  fileLocation: secret.fileLocation,
                  secretString: secret.secretString,
                  secretConfidence: secret.secretConfidence
                }));
                this.secretsSubject.next(transformedSecrets);
              }
              
              // Log metadata before setting
              console.log('Setting metadata with:', {
                activities: response.data.activities?.length || 0,
                services: response.data.services?.length || 0,
                contentProviders: response.data.contentProviders?.length || 0,
                broadcastReceivers: response.data.broadcastReceivers?.length || 0,
                usesLibrary: response.data.usesLibrary?.length || 0,
                permissions: response.data.permissions?.length || 0,
                customPermissions: response.data.customPermissions?.length || 0,
                usesFeatures: response.data.usesFeatures?.length || 0
              });
              
              // Set metadata
              this.metadataSubject.next({
                packageName: response.data.packageName,
                version: response.data.version,
                minSdk: response.data.minSdk,
                targetSdk: response.data.targetSdk,
                permissions: response.data.permissions || [],
                activities: response.data.activities || [],
                services: response.data.services || [],
                contentProviders: response.data.contentProviders || [],
                broadcastReceivers: response.data.broadcastReceivers || [],
                usesLibrary: response.data.usesLibrary || [],
                customPermissions: response.data.customPermissions || [],
                usesFeatures: response.data.usesFeatures || [],
                resourceData: response.data.resourceData || {
                  numberOfStringResource: 0,
                  drawables: {
                    png: 0,
                    jpg: 0,
                    gif: 0,
                    xml: 0
                  },
                  layouts: 0
                }
              });
              
              // Move to results screen
              console.log('Moving to results screen');
              this.setCurrentScreen('results');
            }
          },
          error: (error) => {
            // Continue polling on error
            console.log('Polling for results...', error);
          }
        });
    }, 5000); // Poll every 5 seconds
  }
  
  // Mock data function removed as we're using real API data

  getSecretCountBySeverity(confidence: 'high' | 'low'): number {
    return this.secretsSubject.getValue().filter(s => s.secretConfidence === confidence).length;
  }

  private generateParticlePositions() {
    const positions: Array<{top: string, left: string, size: string, delay: string}> = [];
    
    // Generate 15 particles (reduced from 30 for better performance)
    for (let i = 0; i < 15; i++) {
      positions.push({
        top: `${Math.random() * 100}%`,
        left: `${Math.random() * 100}%`,
        size: `${Math.random() * 8 + 4}px`, // Reduced max size
        delay: `${i * 0.1}s` // Reduced delay between particles
      });
    }
    
    this.particlePositionsSubject.next(positions);
  }
}
