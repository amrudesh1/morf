import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Check, Loader2, X } from 'lucide-react'
import { useScan } from '@/store/scanStore'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'

// The four honest phases of a static scan. The backend drives real progress via
// polling with no per-phase events, so we cycle the active step on a timer purely
// to reassure the user that work is happening — never claiming an exact percentage.
const PHASES = [
  { label: 'Unpack', detail: 'Decompile the package' },
  { label: 'Parse', detail: 'Read manifest & binary' },
  { label: 'Match rules', detail: 'Run every detection rule' },
  { label: 'Compile dossier', detail: 'Assemble the findings' },
]

export function Processing() {
  const { currentFile, selectedPlatform, cancelScan } = useScan()
  const reduce = useReducedMotion()
  const [active, setActive] = useState(0)

  const kind = selectedPlatform === 'ios' ? 'IPA' : 'APK'
  const name = currentFile?.name ?? `your ${kind}`
  const size = currentFile ? `${(currentFile.size / 1_048_576).toFixed(2)} MB` : '—'

  // Reassurance loop: advance the highlighted phase, then hold on the final
  // "Compile dossier" step (real completion is signalled by the polling flow, not us).
  useEffect(() => {
    if (reduce) {
      setActive(PHASES.length - 1)
      return
    }
    const id = setInterval(() => {
      setActive((i) => (i < PHASES.length - 1 ? i + 1 : i))
    }, 2600)
    return () => clearInterval(id)
  }, [reduce])

  const ease = [0.2, 0.8, 0.2, 1] as const
  const rise = (delay: number) =>
    reduce
      ? {}
      : { initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.5, delay, ease } }

  return (
    <div className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-8 px-6 py-16">
      <motion.header className="space-y-3" {...rise(0)}>
        <span className="eyebrow text-signal">Reconnaissance in progress</span>
        <h1 className="font-display text-4xl text-bone md:text-5xl">
          Analyzing <span className="text-signal">{name}</span>
        </h1>
        <p className="max-w-xl font-sans text-base leading-relaxed text-bone-dim">
          MORF is decompiling your {kind} and matching it against every detection rule.
          Hold tight — you can leave this screen open while it works.
        </p>
      </motion.header>

      {/* Redacted document under the signature scan-sweep. */}
      <motion.div
        className="dossier relative overflow-hidden p-6"
        aria-label={`Analyzing ${name}`}
        {...rise(0.08)}
      >
        <div className="space-y-2" aria-hidden>
          {[90, 70, 82, 55, 76].map((w, i) => (
            <div key={i} className="redaction h-3" style={{ width: `${w}%` }}>
              &nbsp;
            </div>
          ))}
        </div>
        {!reduce && (
          <div className="pointer-events-none absolute inset-x-0 top-0 h-16 animate-scan-sweep bg-gradient-to-b from-transparent via-signal/25 to-transparent" />
        )}
      </motion.div>

      {/* Phase stepper — the active phase is highlighted; done phases get a check. */}
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
                'flex items-start gap-3 rounded border p-3 transition-colors',
                current
                  ? 'border-signal/70 bg-signal/10'
                  : done
                    ? 'border-bone-dim/20 bg-transparent'
                    : 'border-bone-dim/10 bg-transparent',
              )}
            >
              <span
                className={cn(
                  'mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border',
                  current
                    ? 'border-signal text-signal'
                    : done
                      ? 'border-signal/60 text-signal/80'
                      : 'border-bone-dim/30 text-bone-dim/50',
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
                    'font-sans text-sm font-semibold',
                    current ? 'text-bone' : done ? 'text-bone-dim' : 'text-bone-dim/60',
                  )}
                >
                  {phase.label}
                </span>
                <span className="font-mono text-[0.68rem] text-bone-dim/70">{phase.detail}</span>
              </span>
            </li>
          )
        })}
      </motion.ol>

      <motion.p className="font-mono text-xs text-bone-dim/70" {...rise(0.24)}>
        Large apps can take a minute. We don&apos;t report an exact percentage — the phases above
        show roughly where we are.
      </motion.p>

      {/* File under scan, as evidence rows. */}
      <motion.div className="space-y-2" {...rise(0.32)}>
        <div className="evidence">
          <span className="k">File</span>
          <span className="lead" />
          <span className="v">{currentFile?.name ?? '—'}</span>
        </div>
        <div className="evidence">
          <span className="k">Size</span>
          <span className="lead" />
          <span className="v">{size}</span>
        </div>
      </motion.div>

      <motion.div {...rise(0.4)}>
        <Button variant="danger" size="md" onClick={cancelScan} aria-label="Cancel scan">
          <X className="h-4 w-4" /> Cancel scan
        </Button>
      </motion.div>
    </div>
  )
}
