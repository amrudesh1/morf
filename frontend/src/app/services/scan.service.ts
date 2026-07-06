import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import {
  BehaviorSubject,
  Observable,
  Observer,
  Subject,
  catchError,
  of,
  switchMap,
  takeUntil,
  takeWhile,
  timer,
} from 'rxjs';

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

interface JobStatusResponse {
  job_id: string;
  status: 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled';
  created_at: string;
  started_at?: string;
  completed_at?: string;
  failed_at?: string;
  error?: string;
  result?: ScanResponse;
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
  private currentScreenSubject = new BehaviorSubject<'splash' | 'upload' | 'processing' | 'results' | 'patterns'>('splash');
  currentScreen$ = this.currentScreenSubject.asObservable();

  // Particle positions for background animation
  private particlePositionsSubject = new BehaviorSubject<Array<{top: string, left: string, size: string, delay: string}>>([]);
  particlePositions$ = this.particlePositionsSubject.asObservable();

  // Cancellation signal for the in-flight poll loop. resetScan/processFile call
  // cancelPolling() to stop a previous job's interval before starting a new one,
  // preventing leaked timers if the user navigates between scans rapidly.
  private cancelPolling$ = new Subject<void>();

  // Set when the user explicitly cancels the in-flight scan via cancelScan().
  // Distinguishes a user-initiated stop (no "taking longer" alert) from the
  // poll budget being exhausted.
  private cancelledByUser = false;

  constructor(private http: HttpClient) {
    this.generateParticlePositions();
  }

  private cancelPolling() {
    this.cancelPolling$.next();
  }

  // Public cancel entry point for the processing screen's Cancel button. Stops
  // the in-flight poll loop and returns the user to the upload screen.
  cancelScan() {
    this.cancelledByUser = true;
    this.cancelPolling();
    this.resetScan();
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

  setCurrentScreen(screen: 'splash' | 'upload' | 'processing' | 'results' | 'patterns') {
    this.currentScreenSubject.next(screen);
  }

  getCurrentScreen() {
    return this.currentScreenSubject.getValue();
  }

  resetScan() {
    this.cancelPolling();
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
    this.http.post<{message: string, job_id: string}>(`${this.apiUrl}/upload`, formData)
      .pipe(
        catchError(error => {
          console.error('Error uploading file:', error);
          let errorMessage = 'Error uploading file. Please try again.';
          
          if (error.error instanceof Blob) {
            // Return a new Observable for Blob error handling
            return new Observable<{message: string, job_id: string}>((observer: Observer<{message: string, job_id: string}>) => {
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
          return of({ message: errorMessage, job_id: '' }); // Return an Observable
        })
      )
      .subscribe({
        next: (response) => {
          console.log('Upload Response:', response);
          // Start polling for results using job ID
          if (response.job_id) {
            this.pollForResultsByJobId(response.job_id);
          } else {
            console.error('No job_id in response');
            this.resetScan();
            alert('Failed to start scan. Please try again.');
          }
        },
        error: (error) => {
          // Error is already handled in catchError
          console.error('Upload error:', error);
        }
      });
  }

  private pollForResultsByJobId(jobId: string) {
    console.log('Starting to poll for results by job ID:', jobId);

    // Cancel any prior poll that might still be in flight before starting a new one.
    this.cancelPolling();
    this.cancelledByUser = false;

    // Exponential backoff: start at 2s, double up to 30s. Total budget ≈ 10min.
    const minDelayMs = 2_000;
    const maxDelayMs = 30_000;
    const totalBudgetMs = 10 * 60_000;
    let nextDelay = minDelayMs;
    let elapsed = 0;
    let attempt = 0;
    let done = false;

    const pollOnce = (): Observable<JobStatusResponse> =>
      this.http.get<JobStatusResponse>(`${this.apiUrl}/results/${jobId}`).pipe(
        catchError((error) => {
          // Only 404 (job not visible yet) and network errors (status 0) are
          // transient — keep polling for those.
          if (error?.status === 404 || error?.status === 0) {
            return of({ job_id: jobId, status: 'queued', created_at: '' } as JobStatusResponse);
          }
          // Any other error is a real failure. The backend returns HTTP 500 for a
          // failed job with body { status: 'failed', error: ... }; surface that
          // instead of masking it as a synthetic 'queued' response so the
          // 'failed' branches downstream can run.
          console.error('Error polling for results:', error);
          return of({
            job_id: jobId,
            status: 'failed',
            created_at: '',
            error: error?.error?.error,
          } as JobStatusResponse);
        }),
      );

    timer(0)
      .pipe(
        switchMap(() =>
          // Recursive scheduler keyed off `nextDelay` so we can vary the gap.
          new Observable<JobStatusResponse>((sub) => {
            let cancelled = false;
            const tick = () => {
              if (cancelled) return;
              attempt++;
              console.log(`Polling API for results (attempt ${attempt}, delay=${nextDelay}ms)`);
              pollOnce().subscribe({
                next: (resp) => {
                  if (cancelled) return;
                  sub.next(resp);
                  if (done) {
                    sub.complete();
                    return;
                  }
                  elapsed += nextDelay;
                  nextDelay = Math.min(nextDelay * 2, maxDelayMs);
                  if (elapsed >= totalBudgetMs) {
                    sub.complete();
                    return;
                  }
                  setTimeout(tick, nextDelay);
                },
                error: (e) => sub.error(e),
              });
            };
            setTimeout(tick, nextDelay);
            return () => {
              cancelled = true;
            };
          }),
        ),
        takeWhile((response) => {
          // inclusive=true: returning false still emits this final value to the
          // consumer, then completes the stream. The terminal states actually
          // gate completion here (instead of relying solely on the inner
          // observable's `done` check) so the control-flow is no longer a no-op.
          if (response.status === 'completed' && response.result) {
            done = true;
            return false;
          }
          if (response.status === 'failed') {
            done = true;
            return false;
          }
          if (response.status === 'cancelled') {
            done = true;
            return false;
          }
          return true;
        }, true),
        takeUntil(this.cancelPolling$),
      )
      .subscribe({
        next: (response) => {
          if (response.status === 'completed' && response.result) {
            const resultData = response.result;
            if (resultData.data?.secrets) {
              const transformedSecrets = resultData.data.secrets.map((secret: BackendSecret) => ({
                type: secret.type,
                lineNo: secret.lineNo,
                secretType: secret.secretType,
                fileLocation: secret.fileLocation,
                secretString: secret.secretString,
                secretConfidence: secret.secretConfidence,
              }));
              this.secretsSubject.next(transformedSecrets);
            }
            this.metadataSubject.next({
              packageName: resultData.data?.packageName || '',
              version: resultData.data?.version || '',
              minSdk: resultData.data?.minSdk || '',
              targetSdk: resultData.data?.targetSdk || '',
              permissions: resultData.data?.permissions || [],
              activities: resultData.data?.activities || [],
              services: resultData.data?.services || [],
              contentProviders: resultData.data?.contentProviders || [],
              broadcastReceivers: resultData.data?.broadcastReceivers || [],
              usesLibrary: resultData.data?.usesLibrary || [],
              customPermissions: resultData.data?.customPermissions || [],
              usesFeatures: resultData.data?.usesFeatures || [],
              resourceData: resultData.data?.resourceData || {
                numberOfStringResource: 0,
                drawables: { png: 0, jpg: 0, gif: 0, xml: 0 },
                layouts: 0,
              },
            });
            this.setCurrentScreen('results');
          } else if (response.status === 'failed') {
            this.resetScan();
            alert(`Scan failed: ${response.error || 'Unknown error'}`);
          } else if (response.status === 'cancelled') {
            this.resetScan();
            alert('Scan was cancelled.');
          }
        },
        complete: () => {
          // A user-initiated cancel already reset the UI via cancelScan(); do
          // not surface the timeout message in that case.
          if (this.cancelledByUser) {
            this.cancelledByUser = false;
            return;
          }
          if (!done) {
            this.resetScan();
            alert('Scan is taking longer than expected. Please check back later.');
          }
        },
      });
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
