import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { getJobResult, uploadFile, ApiError } from '@/lib/api'
import type {
  IosMetadata,
  Metadata,
  Platform,
  Screen,
  Secret,
  ScanResponseData,
  JobStatusResponse,
} from '@/types'

// Polling parameters — ported verbatim from the Angular pollForResultsByJobId.
const MIN_DELAY_MS = 2_000
const MAX_DELAY_MS = 30_000
const TOTAL_BUDGET_MS = 600_000 // 10 minutes

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms)
    signal?.addEventListener('abort', () => {
      clearTimeout(t)
      reject(new DOMException('aborted', 'AbortError'))
    })
  })

interface ScanState {
  currentScreen: Screen
  error: string | null
  selectedPlatform: Platform // user's tab choice (upload)
  currentFile: File | null
  secrets: Secret[]
  metadata: Metadata | null
  iosMetadata: IosMetadata | null
  resultPlatform: Platform // resolved from the backend result
}

interface ScanContextValue extends ScanState {
  setScreen: (s: Screen) => void
  setSelectedPlatform: (p: Platform) => void
  clearError: () => void
  processFile: (file: File) => void
  cancelScan: () => void
  resetScan: () => void
  getSecretCountBySeverity: (c: Secret['secretConfidence']) => number
}

const ScanContext = createContext<ScanContextValue | null>(null)

function mapMetadata(d: ScanResponseData): Metadata {
  return {
    packageName: d.packageName || '',
    version: d.version || '',
    minSdk: d.minSdk || '',
    targetSdk: d.targetSdk || '',
    permissions: d.permissions || [],
    activities: d.activities || [],
    services: d.services || [],
    contentProviders: d.contentProviders || [],
    broadcastReceivers: d.broadcastReceivers || [],
    usesLibrary: d.usesLibrary || [],
    customPermissions: d.customPermissions || [],
    usesFeatures: d.usesFeatures || [],
    resourceData: d.resourceData || {
      numberOfStringResource: 0,
      drawables: { png: 0, jpg: 0, gif: 0, xml: 0 },
      layouts: 0,
    },
  }
}

function mapIos(d: ScanResponseData): IosMetadata {
  return {
    bundleIdentifier: d.bundleIdentifier || '',
    bundleVersion: d.bundleVersion || '',
    deploymentTarget: d.deploymentTarget || '',
    executableName: d.executableName || '',
    architectures: d.architectures || [],
    isEncrypted: !!d.isEncrypted,
    urlSchemes: d.urlSchemes || [],
    entitlements: d.entitlements || {},
    frameworks: d.frameworks || [],
  }
}

export function ScanStoreProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<ScanState>({
    currentScreen: 'splash',
    error: null,
    selectedPlatform: 'android',
    currentFile: null,
    secrets: [],
    metadata: null,
    iosMetadata: null,
    resultPlatform: 'android',
  })
  const patch = useCallback((p: Partial<ScanState>) => setState((s) => ({ ...s, ...p })), [])

  // Cancellation: an AbortController for in-flight fetches + a flag so the poll
  // loop distinguishes a user cancel from a timeout (no timeout error on cancel).
  const abortRef = useRef<AbortController | null>(null)
  const cancelledRef = useRef(false)

  const setScreen = useCallback((s: Screen) => patch({ currentScreen: s }), [patch])
  const setSelectedPlatform = useCallback((p: Platform) => patch({ selectedPlatform: p }), [patch])
  const clearError = useCallback(() => patch({ error: null }), [patch])
  const emitError = useCallback((msg: string) => patch({ error: msg }), [patch])

  const cancelPolling = useCallback(() => {
    abortRef.current?.abort()
    abortRef.current = null
  }, [])

  const resetScan = useCallback(() => {
    cancelPolling()
    setState((s) => ({
      ...s,
      currentScreen: 'upload',
      currentFile: null,
      secrets: [],
      metadata: null,
      iosMetadata: null,
      resultPlatform: 'android',
    }))
  }, [cancelPolling])

  const cancelScan = useCallback(() => {
    cancelledRef.current = true
    resetScan()
  }, [resetScan])

  const completeWith = useCallback(
    (data: ScanResponseData) => {
      const platform: Platform = data.platform === 'ios' ? 'ios' : 'android'
      const secrets: Secret[] = (data.secrets || []).map((s) => ({
        type: s.type,
        lineNo: s.lineNo,
        secretType: s.secretType,
        fileLocation: s.fileLocation,
        secretString: s.secretString,
        secretConfidence: s.secretConfidence,
      }))
      patch({
        secrets,
        metadata: mapMetadata(data),
        iosMetadata: platform === 'ios' ? mapIos(data) : null,
        resultPlatform: platform,
        currentScreen: 'results',
      })
    },
    [patch],
  )

  const pollForResults = useCallback(
    async (jobId: string) => {
      const ctrl = new AbortController()
      abortRef.current = ctrl
      const start = Date.now()
      let delay = MIN_DELAY_MS
      try {
        // First poll after a short delay, then exponential backoff up to MAX.
        for (;;) {
          await sleep(delay, ctrl.signal)
          if (Date.now() - start >= TOTAL_BUDGET_MS) {
            if (!cancelledRef.current) {
              emitError('The scan is taking longer than expected. Please try again.')
              resetScan()
            }
            return
          }
          let resp: JobStatusResponse
          try {
            resp = await getJobResult(jobId, ctrl.signal)
          } catch (err) {
            if (err instanceof DOMException && err.name === 'AbortError') return
            // 404 (job not visible yet) or network error → keep polling.
            if (err instanceof ApiError && err.status !== 404 && err.status !== 0) {
              emitError(err.message || 'Scan failed.')
              resetScan()
              return
            }
            delay = Math.min(delay * 2, MAX_DELAY_MS)
            continue
          }
          if (resp.status === 'completed' && resp.result) {
            completeWith(resp.result.data)
            abortRef.current = null
            return
          }
          if (resp.status === 'failed') {
            emitError(resp.error || 'Scan failed.')
            resetScan()
            return
          }
          if (resp.status === 'cancelled') {
            if (!cancelledRef.current) emitError('Scan was cancelled.')
            resetScan()
            return
          }
          delay = Math.min(delay * 2, MAX_DELAY_MS)
        }
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') return
        emitError('Scan failed unexpectedly.')
        resetScan()
      }
    },
    [completeWith, emitError, resetScan],
  )

  const processFile = useCallback(
    (file: File) => {
      cancelledRef.current = false
      clearError()
      cancelPolling()
      patch({ currentFile: file, currentScreen: 'processing', secrets: [], metadata: null, iosMetadata: null })
      const ctrl = new AbortController()
      abortRef.current = ctrl
      uploadFile(file, ctrl.signal)
        .then((res) => {
          if (res.job_id) {
            void pollForResults(res.job_id)
          } else {
            emitError('Failed to start scan.')
            resetScan()
          }
        })
        .catch((err) => {
          if (err instanceof DOMException && err.name === 'AbortError') return
          emitError(err instanceof ApiError ? err.message : 'Failed to upload file.')
          resetScan()
        })
    },
    [cancelPolling, clearError, emitError, patch, pollForResults, resetScan],
  )

  const getSecretCountBySeverity = useCallback(
    (c: Secret['secretConfidence']) => state.secrets.filter((s) => s.secretConfidence === c).length,
    [state.secrets],
  )

  const value = useMemo<ScanContextValue>(
    () => ({
      ...state,
      setScreen,
      setSelectedPlatform,
      clearError,
      processFile,
      cancelScan,
      resetScan,
      getSecretCountBySeverity,
    }),
    [state, setScreen, setSelectedPlatform, clearError, processFile, cancelScan, resetScan, getSecretCountBySeverity],
  )

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>
}

export function useScan(): ScanContextValue {
  const ctx = useContext(ScanContext)
  if (!ctx) throw new Error('useScan must be used within ScanStoreProvider')
  return ctx
}
