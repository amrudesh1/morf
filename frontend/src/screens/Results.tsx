import { useScan } from '@/store/scanStore'
import { cn } from '@/lib/cn'
import type { Confidence } from '@/types'

const sevClass: Record<Confidence, string> = {
  high: 'sev--high',
  medium: 'sev--medium',
  low: 'sev--low',
}
const stampClass: Record<Confidence, string> = {
  high: 'stamp',
  medium: 'stamp stamp--signal',
  low: 'stamp stamp--muted',
}

function cleanPath(p: string): string {
  const m = p.indexOf('output/')
  return m >= 0 ? p.slice(m) : p
}

export function Results() {
  const { secrets, resultPlatform, iosMetadata, metadata, currentFile, resetScan } = useScan()

  return (
    <div className="mx-auto flex min-h-screen max-w-4xl flex-col gap-8 px-6 py-12">
      <div className="flex items-center justify-between">
        <span className="font-display text-3xl">MORF</span>
        <button
          onClick={resetScan}
          className="font-mono text-xs uppercase tracking-widest text-bone-dim hover:text-signal"
        >
          New case →
        </button>
      </div>

      {/* Dossier masthead */}
      <div className="dossier flex flex-wrap items-end justify-between gap-6 p-6">
        <div>
          <span className="eyebrow">Reconnaissance complete</span>
          <div className="flex items-baseline gap-3">
            <span className="font-display text-7xl text-oxblood">{secrets.length}</span>
            <span className="font-display text-3xl text-bone">Exposed</span>
          </div>
        </div>
        <div className="space-y-1 text-right">
          <span className={cn(resultPlatform === 'ios' ? 'stamp stamp--signal' : 'stamp stamp--muted')}>
            {resultPlatform === 'ios' ? 'iOS' : 'Android'}
          </span>
          <p className="font-mono text-xs text-bone-dim">{currentFile?.name}</p>
        </div>
      </div>

      {/* iOS metadata */}
      {resultPlatform === 'ios' && iosMetadata && (
        <div className="dossier space-y-3 p-6">
          <span className="eyebrow">Target</span>
          <div className="grid gap-2 md:grid-cols-2">
            <Ev k="Bundle ID" v={iosMetadata.bundleIdentifier} />
            <Ev k="Version" v={iosMetadata.bundleVersion} />
            <Ev k="Min OS" v={iosMetadata.deploymentTarget} />
            <Ev k="Executable" v={iosMetadata.executableName} />
            <Ev k="Architectures" v={iosMetadata.architectures.join(', ')} />
            <div className="evidence">
              <span className="k">Encryption</span>
              <span className="lead" />
              <span className={iosMetadata.isEncrypted ? 'stamp' : 'stamp stamp--muted'}>
                {iosMetadata.isEncrypted ? 'Encrypted' : 'Exposed'}
              </span>
            </div>
          </div>
          {iosMetadata.urlSchemes.length > 0 && (
            <p className="font-mono text-xs text-bone-dim">
              URL schemes: <span className="text-signal">{iosMetadata.urlSchemes.join('  ·  ')}</span>
            </p>
          )}
          {iosMetadata.frameworks.length > 0 && (
            <p className="font-mono text-xs text-bone-dim">Frameworks: {iosMetadata.frameworks.length}</p>
          )}
        </div>
      )}

      {/* Android metadata */}
      {resultPlatform === 'android' && metadata && (
        <div className="dossier grid gap-2 p-6 md:grid-cols-2">
          <Ev k="Package" v={metadata.packageName} />
          <Ev k="Version" v={metadata.version} />
          <Ev k="Min SDK" v={metadata.minSdk} />
          <Ev k="Target SDK" v={metadata.targetSdk} />
        </div>
      )}

      {/* Discovered Secrets */}
      <div className="dossier p-6">
        <span className="eyebrow">Discovered secrets</span>
        <div className="mt-4 space-y-3">
          {secrets.length === 0 && <p className="font-mono text-sm text-bone-dim">No secrets exposed.</p>}
          {secrets.map((s, i) => (
            <div key={`${s.fileLocation}:${s.lineNo}:${i}`} className="rounded border border-ink-700 bg-ink-800/60 p-4">
              <div className="flex items-center gap-3">
                <span className={cn('sev', sevClass[s.secretConfidence])} />
                <span className="font-display text-lg text-bone">{s.secretType || s.type}</span>
                <span className={cn('ml-auto', stampClass[s.secretConfidence])}>{s.secretConfidence}</span>
              </div>
              <div className="mt-3 flex items-center gap-3">
                <span className="font-mono text-xs text-bone-dim">value</span>
                <span
                  className="redaction font-mono text-sm"
                  tabIndex={0}
                  role="button"
                  title="Reveal secret"
                >
                  {s.secretString}
                </span>
                <button
                  onClick={() => navigator.clipboard?.writeText(s.secretString)}
                  className="ml-auto font-mono text-[0.65rem] uppercase tracking-widest text-bone-dim hover:text-signal"
                >
                  Copy
                </button>
              </div>
              <p className="mt-2 font-mono text-xs text-bone-dim">
                {cleanPath(s.fileLocation)}:{s.lineNo}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function Ev({ k, v }: { k: string; v: string }) {
  return (
    <div className="evidence">
      <span className="k">{k}</span>
      <span className="lead" />
      <span className="v">{v || '—'}</span>
    </div>
  )
}
