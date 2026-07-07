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
import { environment } from '../../environments/environment';

// TODO(codegen): the request/response DTOs below (BackendSecret, ScanResponse,
// JobStatusResponse, etc.) are hand-maintained mirrors of the schemas in
// morf/docs/api/openapi.yaml. They should ideally be generated from that spec
// (e.g. openapi-typescript / @openapitools/openapi-generator-cli) so they can't
// drift. A generator is intentionally NOT wired in here to avoid adding heavy
// build tooling; keep these types in sync with the OpenAPI spec by hand until
// codegen is added as a separate change.

// Backend secret format
interface BackendSecret {
  type: string;
  lineNo: number;
  secretType: string;
  fileLocation: string;
  secretString: string;
  secretConfidence: 'high' | 'medium' | 'low';
}

// Frontend format matches backend format for simplicity
export interface Secret {
  type: string;
  lineNo: number;
  secretType: string;
  fileLocation: string;
  secretString: string;
  secretConfidence: 'high' | 'medium' | 'low';
}

// iOS-specific metadata view model for .ipa scans. The backend emits these
// fields flattened onto the result `data` object (response.IOSMetadataHandler);
// this interface is the normalized shape the results screen consumes:
// { bundleIdentifier, bundleVersion, deploymentTarget, executableName,
//   architectures: string[], isEncrypted: bool, urlSchemes: string[],
//   entitlements: object, frameworks: string[] }.
export interface IosMetadata {
  bundleIdentifier: string;
  bundleVersion: string;
  deploymentTarget: string;
  executableName: string;
  architectures: string[];
  isEncrypted: boolean;
  urlSchemes: string[];
  // entitlements is a free-form key/value object whose values can be strings,
  // booleans, numbers, or nested arrays/objects (e.g. keychain-access-groups).
  entitlements: Record<string, unknown>;
  frameworks: string[];
}

interface ScanResponse {
  message: string;
  data: {
    // Platform of the scanned package. The backend stamps this inside `data`
    // (Android scans may omit it, treated as 'android'; iOS scans set 'ios').
    platform?: 'android' | 'ios';
    fileName: string;
    packageName: string;
    version: string;
    minSdk: string;
    targetSdk: string;
    permissions: string[];
    secretCount: number;
    secrets: BackendSecret[];
    createdAt: string;
    // iOS metadata fields, present only on iOS scans (data.platform === 'ios').
    // The backend (response.IOSMetadataHandler.TransformMetadata) flattens
    // these directly onto `data`, alongside the shared fields above — there is
    // no nested `iosMetadata` object in the wire envelope.
    bundleIdentifier?: string;
    bundleVersion?: string;
    deploymentTarget?: string;
    executableName?: string;
    architectures?: string[];
    isEncrypted?: boolean;
    urlSchemes?: string[];
    entitlements?: Record<string, unknown>;
    frameworks?: string[];
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
  // API base URL. Sourced from the environment (default '/api', a relative path
  // that goes through the nginx reverse proxy). See src/environments/.
  private apiUrl = environment.apiBaseUrl;

  // Error surfacing. Instead of blocking alert() dialogs, scan errors are pushed
  // onto this observable so components (e.g. the processing screen) can render
  // them inline. null means "no error". Callers should reset it to null before
  // starting a new scan; clearError() does that.
  private scanErrorSubject = new BehaviorSubject<string | null>(null);
  scanError$ = this.scanErrorSubject.asObservable();

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

  // iOS-specific metadata (null for Android scans or before a scan completes).
  private iosMetadataSubject = new BehaviorSubject<IosMetadata | null>(null);
  iosMetadata$ = this.iosMetadataSubject.asObservable();

  // Resolved platform of the most recent scan result. Distinct from the
  // user-selected platform (selectedPlatform$): this reflects what the backend
  // actually reported, so the results screen renders the correct sections even
  // if the selection state drifts.
  private resultPlatformSubject = new BehaviorSubject<'android' | 'ios'>('android');
  resultPlatform$ = this.resultPlatformSubject.asObservable();

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

  // Push an error message onto scanError$ so subscribed components can render it
  // inline. Replaces the old blocking alert() calls.
  private emitError(message: string) {
    this.scanErrorSubject.next(message);
  }

  // Clear any surfaced scan error. Components may call this (e.g. when the user
  // dismisses a banner); it is also called at the start of every new scan.
  clearError() {
    if (this.scanErrorSubject.getValue() !== null) {
      this.scanErrorSubject.next(null);
    }
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
    this.iosMetadataSubject.next(null);
    this.resultPlatformSubject.next('android');
    this.setCurrentScreen('upload');
  }

  processFile(file: File) {
    console.log('Processing file:', file.name);
    // Clear any error left over from a previous scan before starting a new one.
    this.clearError();
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
                this.emitError(errorMessage);
                observer.error(error);
              };
              reader.readAsText(error.error);
            });
          } else if (error.error?.error) {
            errorMessage = error.error.error;
          }

          this.resetScan();
          this.emitError(errorMessage);
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
            this.emitError('Failed to start scan. Please try again.');
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
            // Resolve the platform from the response envelope, defaulting to
            // 'android' when the backend omits it (Android scans). The backend
            // stamps `platform` inside `data`, not at the top level.
            const platform = resultData.data?.platform === 'ios' ? 'ios' : 'android';
            this.resultPlatformSubject.next(platform);
            // The backend flattens the iOS metadata fields directly onto `data`
            // (see response.IOSMetadataHandler); assemble the IosMetadata view
            // model from those flat fields rather than a nested object.
            this.iosMetadataSubject.next(
              platform === 'ios' && resultData.data
                ? {
                    bundleIdentifier: resultData.data.bundleIdentifier || '',
                    bundleVersion: resultData.data.bundleVersion || '',
                    deploymentTarget: resultData.data.deploymentTarget || '',
                    executableName: resultData.data.executableName || '',
                    architectures: resultData.data.architectures || [],
                    isEncrypted: !!resultData.data.isEncrypted,
                    urlSchemes: resultData.data.urlSchemes || [],
                    entitlements: resultData.data.entitlements || {},
                    frameworks: resultData.data.frameworks || [],
                  }
                : null,
            );
            this.setCurrentScreen('results');
          } else if (response.status === 'failed') {
            this.resetScan();
            this.emitError(`Scan failed: ${response.error || 'Unknown error'}`);
          } else if (response.status === 'cancelled') {
            this.resetScan();
            this.emitError('Scan was cancelled.');
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
            this.emitError('Scan is taking longer than expected. Please check back later.');
          }
        },
      });
  }
  
  // Mock data function removed as we're using real API data

  getSecretCountBySeverity(confidence: 'high' | 'medium' | 'low'): number {
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
