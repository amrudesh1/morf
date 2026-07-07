import { useEffect, useState } from 'react'
import { useScan } from '@/store/scanStore'
import { patternsApi } from '@/lib/api'
import type { PatternFile } from '@/types'
import { cn } from '@/lib/cn'

export function PatternManagement() {
  const { setScreen } = useScan()
  const [files, setFiles] = useState<PatternFile[]>([])
  const [selected, setSelected] = useState<PatternFile | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const load = () => {
    setLoading(true)
    patternsApi
      .list()
      .then((r) => {
        setFiles(r.files)
        setError(null)
      })
      .catch((e) => setError(e?.message ?? 'Failed to load rules'))
      .finally(() => setLoading(false))
  }
  useEffect(load, [])

  return (
    <div className="mx-auto flex min-h-screen max-w-5xl flex-col gap-6 px-6 py-12">
      <div className="flex items-center justify-between">
        <div>
          <span className="eyebrow">MORF · Mobile Reconnaissance Framework</span>
          <h1 className="font-display text-4xl text-bone">Detection rules ledger</h1>
        </div>
        <button
          onClick={() => setScreen('upload')}
          className="font-mono text-xs uppercase tracking-widest text-bone-dim hover:text-signal"
        >
          ← Back to upload
        </button>
      </div>

      <button
        onClick={load}
        disabled={loading}
        className="self-start font-mono text-xs uppercase tracking-widest text-signal disabled:opacity-50"
      >
        {loading ? 'Reloading…' : 'Reload ledger'}
      </button>

      {error && <p className="font-mono text-sm text-oxblood">{error}</p>}

      <div className="grid gap-6 md:grid-cols-[1fr_2fr]">
        <div className="dossier p-4">
          <span className="eyebrow">Case folders</span>
          <ul className="mt-3 space-y-1">
            {files.map((f) => (
              <li key={f.filename}>
                <button
                  onClick={() => setSelected(f)}
                  className={cn(
                    'w-full rounded px-3 py-2 text-left font-mono text-sm',
                    selected?.filename === f.filename ? 'bg-signal/10 text-signal' : 'text-bone-dim hover:text-bone',
                  )}
                >
                  {f.filename} · {f.patterns.length}
                </button>
              </li>
            ))}
            {files.length === 0 && !loading && (
              <li className="font-mono text-xs text-bone-dim">No rule files.</li>
            )}
          </ul>
        </div>

        <div className="dossier p-4">
          <span className="eyebrow">Ledger entries</span>
          <div className="mt-3 space-y-2">
            {selected?.patterns.map((p) => (
              <div key={p.name} className="flex items-center gap-3 border-b border-ink-700 pb-2">
                <span className={cn('sev', `sev--${p.confidence}`)} />
                <span className="font-mono text-sm text-bone">{p.name}</span>
                <span className={cn('ml-auto', p.enabled ? 'stamp stamp--signal' : 'stamp stamp--muted')}>
                  {p.enabled ? 'On' : 'Off'}
                </span>
              </div>
            ))}
            {!selected && <p className="font-mono text-sm text-bone-dim">Open a case folder to read its rules.</p>}
          </div>
        </div>
      </div>
    </div>
  )
}
