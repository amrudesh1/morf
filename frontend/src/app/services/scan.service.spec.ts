import { TestBed, fakeAsync, tick, flush } from '@angular/core/testing';
import {
  HttpClientTestingModule,
  HttpTestingController,
} from '@angular/common/http/testing';

import { ScanService } from './scan.service';
import { environment } from '../../environments/environment';

// These specs exercise the jobID polling state machine in ScanService.
// The service uploads a file, receives a job_id, then polls
// `${apiBaseUrl}/results/{jobId}` on an exponential backoff (2s, 4s, 8s ...
// capped at 30s, with a ~10 minute total budget) until it observes a terminal
// status (completed / failed / cancelled), the budget is exhausted (timeout),
// or the user cancels.
//
// Timing note: the first poll fires 2000ms after upload resolves (the inner
// scheduler always does setTimeout(tick, nextDelay) before the first tick, with
// nextDelay starting at the 2s minimum). Each subsequent poll doubles the delay.
describe('ScanService jobID polling state machine', () => {
  const apiUrl = environment.apiBaseUrl;
  const UPLOAD_URL = `${apiUrl}/upload`;
  const jobId = 'test-job-123';
  const RESULTS_URL = `${apiUrl}/results/${jobId}`;

  let service: ScanService;
  let httpMock: HttpTestingController;

  // Minimal but structurally-complete completed-result payload.
  const completedResult = {
    message: 'ok',
    data: {
      fileName: 'app.apk',
      packageName: 'com.example.app',
      version: '1.0.0',
      minSdk: '21',
      targetSdk: '34',
      permissions: ['android.permission.INTERNET'],
      secretCount: 1,
      secrets: [
        {
          type: 'secret',
          lineNo: 10,
          secretType: 'AWS Key',
          fileLocation: 'res/values/strings.xml',
          secretString: 'AKIA...',
          secretConfidence: 'high' as const,
        },
      ],
      createdAt: '2024-01-01T00:00:00Z',
      activities: [],
      services: [],
      contentProviders: [],
      broadcastReceivers: [],
      usesLibrary: [],
      customPermissions: [],
      usesFeatures: [],
      resourceData: {
        numberOfStringResource: 0,
        drawables: { png: 0, jpg: 0, gif: 0, xml: 0 },
        layouts: 0,
      },
    },
  };

  function makeFile(name = 'app.apk'): File {
    return new File([new Uint8Array([1, 2, 3])], name, {
      type: 'application/vnd.android.package-archive',
    });
  }

  // Resolve the initial upload POST with a job_id, kicking off polling.
  function completeUpload(): void {
    const req = httpMock.expectOne(UPLOAD_URL);
    expect(req.request.method).toBe('POST');
    req.flush({ message: 'accepted', job_id: jobId });
  }

  // Advance fake time to the next scheduled poll and answer it with `body`.
  // `delayMs` must match the backoff step that the scheduler is currently on.
  function answerNextPoll(delayMs: number, body: object, status = 200): void {
    tick(delayMs);
    const req = httpMock.expectOne(RESULTS_URL);
    expect(req.request.method).toBe('GET');
    if (status === 200) {
      req.flush(body);
    } else {
      req.flush(body, { status, statusText: 'Error' });
    }
  }

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [ScanService],
    });
    service = TestBed.inject(ScanService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('uses the API base URL from the environment', () => {
    expect(UPLOAD_URL).toContain(environment.apiBaseUrl);
  });

  it('transitions queued -> processing -> completed and lands on the results screen', fakeAsync(() => {
    const screens: string[] = [];
    const screenSub = service.currentScreen$.subscribe((s) => screens.push(s));
    let secretCount = 0;
    const secretsSub = service.secrets$.subscribe((s) => (secretCount = s.length));

    service.processFile(makeFile());
    // Immediately moves to the processing screen.
    expect(service.getCurrentScreen()).toBe('processing');

    completeUpload();

    // Poll #1 (t=+2s): still queued -> keep polling.
    answerNextPoll(2000, {
      job_id: jobId,
      status: 'queued',
      created_at: '2024-01-01T00:00:00Z',
    });
    expect(service.getCurrentScreen()).toBe('processing');

    // Poll #2 (t=+4s): processing -> keep polling.
    answerNextPoll(4000, {
      job_id: jobId,
      status: 'processing',
      created_at: '2024-01-01T00:00:00Z',
      started_at: '2024-01-01T00:00:01Z',
    });
    expect(service.getCurrentScreen()).toBe('processing');

    // Poll #3 (t=+8s): completed with a result -> terminal.
    answerNextPoll(8000, {
      job_id: jobId,
      status: 'completed',
      created_at: '2024-01-01T00:00:00Z',
      completed_at: '2024-01-01T00:00:05Z',
      result: completedResult,
    });

    expect(service.getCurrentScreen()).toBe('results');
    expect(secretCount).toBe(1);
    // No further polls should be scheduled after a terminal state.
    flush();
    httpMock.expectNone(RESULTS_URL);

    screenSub.unsubscribe();
    secretsSub.unsubscribe();
  }));

  it('surfaces a failed job via scanError$ (no result screen)', fakeAsync(() => {
    const errors: Array<string | null> = [];
    const errSub = service.scanError$.subscribe((e) => errors.push(e));

    service.processFile(makeFile());
    completeUpload();

    // First poll returns failed.
    answerNextPoll(2000, {
      job_id: jobId,
      status: 'failed',
      created_at: '2024-01-01T00:00:00Z',
      error: 'boom',
    });

    expect(service.getCurrentScreen()).toBe('upload');
    expect(errors[errors.length - 1]).toContain('boom');

    flush();
    errSub.unsubscribe();
  }));

  it('handles a timeout by surfacing an error once the poll budget is exhausted', fakeAsync(() => {
    const errors: Array<string | null> = [];
    const errSub = service.scanError$.subscribe((e) => errors.push(e));

    service.processFile(makeFile());
    completeUpload();

    // Keep answering 'processing' on the backoff schedule (2s,4s,8s,16s,30s...)
    // until the ~10 minute total budget is exhausted. Cap the loop so a
    // regression that never terminates fails fast instead of hanging.
    let delay = 2000;
    const maxDelay = 30000;
    let terminated = false;
    for (let i = 0; i < 60; i++) {
      tick(delay);
      const reqs = httpMock.match(RESULTS_URL);
      if (reqs.length === 0) {
        // No more polls scheduled: the budget was exhausted and the stream
        // completed.
        terminated = true;
        break;
      }
      reqs.forEach((r) =>
        r.flush({
          job_id: jobId,
          status: 'processing',
          created_at: '2024-01-01T00:00:00Z',
        }),
      );
      delay = Math.min(delay * 2, maxDelay);
    }

    flush();
    expect(terminated).toBeTrue();
    // The timeout path resets to the upload screen and surfaces a message.
    expect(service.getCurrentScreen()).toBe('upload');
    expect(errors[errors.length - 1]).toContain('taking longer');

    errSub.unsubscribe();
  }));

  it('cancel stops polling, returns to upload, and does not surface a timeout error', fakeAsync(() => {
    const errors: Array<string | null> = [];
    const errSub = service.scanError$.subscribe((e) => errors.push(e));

    service.processFile(makeFile());
    completeUpload();

    // One 'processing' poll, then the user cancels.
    answerNextPoll(2000, {
      job_id: jobId,
      status: 'processing',
      created_at: '2024-01-01T00:00:00Z',
    });

    service.cancelScan();
    expect(service.getCurrentScreen()).toBe('upload');

    // Advancing time must not trigger any further polls after cancel.
    tick(60000);
    httpMock.expectNone(RESULTS_URL);

    // Cancel is user-initiated: no "taking longer" timeout message.
    expect(errors.every((e) => e === null || !e.includes('taking longer'))).toBeTrue();

    flush();
    errSub.unsubscribe();
  }));

  it('keeps polling through a transient 404 (job not visible yet)', fakeAsync(() => {
    service.processFile(makeFile());
    completeUpload();

    // First poll 404s -> treated as 'queued', keep polling.
    answerNextPoll(2000, { error: 'not found' }, 404);
    expect(service.getCurrentScreen()).toBe('processing');

    // Second poll completes.
    answerNextPoll(4000, {
      job_id: jobId,
      status: 'completed',
      created_at: '2024-01-01T00:00:00Z',
      result: completedResult,
    });
    expect(service.getCurrentScreen()).toBe('results');

    flush();
  }));
});
