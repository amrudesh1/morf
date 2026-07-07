import { motion, useReducedMotion } from 'framer-motion'
import { Check, Loader2, X } from 'lucide-react'
import { useScan } from '@/store/scanStore'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'

// The four stages of a static scan. The active step is driven by the REAL backend
// phase (polled via scanPhase), not a timer — so the user sees which stage is
// actually running. `key` matches the phase string the worker reports.
const PHASES = [
  { key: 'unpacking', label: 'Unpack', detail: 'Decompile the package' },
  { key: 'parsing', label: 'Parse', detail: 'Read manifest & binary' },
  { key: 'scanning', label: 'Match rules', detail: 'Run every detection rule' },
  { key: 'compiling', label: 'Compile dossier', detail: 'Assemble the findings' },
]
const PHASE_INDEX: Record<string, number> = { unpacking: 0, parsing: 1, scanning: 2, compiling: 3 }

// Widths for the shimmering placeholder document "lines" under the scan-sweep.
const DOC_BARS = [92, 74, 84, 58, 78, 66]

export function Processing() {
  const { currentFile, selectedPlatform, cancelScan, scanPhase } = useScan()
  const reduce = useReducedMotion()

  const kind = selectedPlatform === 'ios' ? 'IPA' : 'APK'
  const name = currentFile?.name ?? `your ${kind}`
  const size = currentFile ? `${(currentFile.size / 1_048_576).toFixed(2)} MB` : '—'

  // The active step reflects the REAL backend stage. Before the first phase
  // lands (job still queued) we sit on step 0 with its spinner.
  const active = scanPhase && scanPhase in PHASE_INDEX ? PHASE_INDEX[scanPhase] : 0

  const ease = [0.2, 0.8, 0.2, 1] as const
  const rise = (delay: number) =>
    reduce
      ? {}
      : { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.5, delay, ease } }

  return (
    <div className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-8 px-6 py-16">
      <motion.header className="space-y-3" {...rise(0)}>
        <span className="eyebrow">Reconnaissance in progress</span>
        <h1 className="font-display text-4xl font-semibold text-txt md:text-5xl">
          Analyzing <span className="gradient-text">{name}</span>
        </h1>
        <p className="max-w-xl text-base leading-relaxed text-txt-muted">
          MORF is decompiling your {kind} and matching it against every detection rule.
          Hold tight — you can leave this screen open while it works.
        </p>
      </motion.header>

      {/* Placeholder document under the signature indigo→cyan scan-sweep. */}
      <motion.div
        className="card relative overflow-hidden p-6"
        aria-label={`Analyzing ${name}`}
        {...rise(0.08)}
      >
        <div className="space-y-2.5" aria-hidden>
          {DOC_BARS.map((w, i) => (
            <div
              key={i}
              className={cn(
                'h-3 rounded bg-gradient-to-r from-surface-hi via-line-hi to-surface-hi',
                !reduce && 'animate-shimmer',
              )}
              style={{ width: `${w}%`, backgroundSize: '200% 100%' }}
            />
          ))}
        </div>
        {!reduce && (
          <div className="pointer-events-none absolute inset-x-0 top-0 h-20 animate-scan-sweep bg-gradient-to-b from-transparent via-indigo/25 to-cyan/20" />
        )}
      </motion.div>

      {/* Phase stepper — the active phase gets an indigo ring; done phases a cyan check. */}
      <motion.ol
        className="grid grid-cols-1 gap-2 sm:grid-cols-2"
        aria-label="Scan phases"
        aria-live="polite"
        {...rise(0.16)}
      >
        {PHASES.map((phase, i) => {
          const done = i < active
          const current = i === active
          return (
            <li
              key={phase.label}
              aria-current={current ? 'step' : undefined}
              className={cn(
                'card flex items-start gap-3 p-3 transition-colors',
                current
                  ? 'border-indigo/60 shadow-glow'
                  : done
                    ? 'border-line-hi'
                    : 'border-line opacity-70',
              )}
            >
              <span
                className={cn(
                  'mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border',
                  current
                    ? 'border-indigo text-indigo-hi'
                    : done
                      ? 'border-cyan/50 text-cyan'
                      : 'border-line-hi text-txt-dim',
                )}
                aria-hidden
              >
                {done ? (
                  <Check className="h-3 w-3" />
                ) : current ? (
                  <Loader2 className={cn('h-3 w-3', !reduce && 'animate-spin')} />
                ) : (
                  <span className="font-mono text-[0.6rem]">{i + 1}</span>
                )}
              </span>
              <span className="flex flex-col">
                <span
                  className={cn(
                    'font-display text-sm font-semibold',
                    current ? 'text-txt' : done ? 'text-txt-muted' : 'text-txt-dim',
                  )}
                >
                  {phase.label}
                </span>
                <span className="font-mono text-[0.68rem] text-txt-dim">{phase.detail}</span>
              </span>
            </li>
          )
        })}
      </motion.ol>

      <motion.p className="font-mono text-xs text-txt-dim" {...rise(0.24)}>
        Large apps can take a minute. The highlighted step above is the stage MORF is running right now.
      </motion.p>

      {/* File under scan. */}
      <motion.div className="card flex flex-wrap items-center gap-8 p-5" {...rise(0.32)}>
        <div className="stat min-w-0">
          <span className="k">File</span>
          <span className="v break-all font-mono text-sm">{currentFile?.name ?? '—'}</span>
        </div>
        <div className="stat">
          <span className="k">Size</span>
          <span className="v font-mono text-sm">{size}</span>
        </div>
        <span className={cn('badge ml-auto', selectedPlatform === 'ios' ? 'badge--cyan' : 'badge--indigo')}>
          {selectedPlatform === 'ios' ? 'iOS' : 'Android'}
        </span>
      </motion.div>

      <motion.div {...rise(0.4)}>
        <Button variant="danger" size="md" onClick={cancelScan} aria-label="Cancel scan">
          <X className="h-4 w-4" /> Cancel scan
        </Button>
      </motion.div>
    </div>
  )
}
