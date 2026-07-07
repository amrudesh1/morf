import { useScan } from '@/store/scanStore'

export function Processing() {
  const { currentFile, selectedPlatform, cancelScan } = useScan()
  const size = currentFile ? `${(currentFile.size / 1_048_576).toFixed(2)} MB` : '—'

  return (
    <div className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-8 px-6">
      <span className="eyebrow">Reconnaissance in progress</span>
      <h1 className="font-display text-5xl text-bone">
        Scanning {selectedPlatform === 'ios' ? 'IPA' : 'APK'}
      </h1>

      <div className="dossier relative overflow-hidden p-6" aria-label="Analyzing document">
        <div className="space-y-2" aria-hidden>
          {[90, 70, 82, 55, 76].map((w, i) => (
            <div key={i} className="redaction h-3" style={{ width: `${w}%` }}>
              &nbsp;
            </div>
          ))}
        </div>
        <div className="pointer-events-none absolute inset-x-0 top-0 h-16 animate-scan-sweep bg-gradient-to-b from-transparent via-signal/25 to-transparent" />
      </div>

      <div className="space-y-1 font-mono text-sm" aria-live="polite">
        <p className="text-bone-dim">[ok] Package unpacked</p>
        <p className="text-bone-dim">[ok] Manifest &amp; components parsed</p>
        <p className="text-signal">[..] Matching detection rules</p>
        <p className="text-bone-dim/60">[ ] Compiling dossier</p>
      </div>

      <div className="space-y-2">
        <div className="evidence">
          <span className="k">Evidence</span>
          <span className="lead" />
          <span className="v">{currentFile?.name ?? '—'}</span>
        </div>
        <div className="evidence">
          <span className="k">Size</span>
          <span className="lead" />
          <span className="v">{size}</span>
        </div>
      </div>

      <button
        onClick={cancelScan}
        className="self-start font-mono text-xs uppercase tracking-widest text-oxblood hover:text-oxblood/80"
      >
        Cancel scan
      </button>
    </div>
  )
}
