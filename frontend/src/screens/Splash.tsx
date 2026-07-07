import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { ArrowRight, ScrollText } from 'lucide-react'
import { useScan } from '@/store/scanStore'
import { Button } from '@/components/ui/Button'

const STEPS = [
  { n: '01', label: 'Unpack', detail: 'Decompile the .apk / .ipa' },
  { n: '02', label: 'Scan', detail: 'Match every detection rule' },
  { n: '03', label: 'Dossier', detail: 'Review exposed secrets' },
]

// A real landing hero: it states what MORF does and dramatizes the thesis — the
// signature redaction bar reveals a "leaked" key on a loop — then hands control
// to the user (a clear CTA, no forced timer).
export function Splash() {
  const { setScreen } = useScan()
  const reduce = useReducedMotion()
  const [revealed, setRevealed] = useState(false)

  useEffect(() => {
    if (reduce) {
      setRevealed(true)
      return
    }
    // Orchestrated moment: strike → reveal → re-redact, gently looping.
    let on = false
    const id = setInterval(() => {
      on = !on
      setRevealed(on)
    }, 2200)
    return () => clearInterval(id)
  }, [reduce])

  const ease = [0.2, 0.8, 0.2, 1] as const
  const rise = (delay: number) =>
    reduce
      ? {}
      : { initial: { opacity: 0, y: 14 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.6, delay, ease } }

  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden px-6 py-16 text-center">
      <motion.span className="eyebrow" {...rise(0)}>
        Case file · Classified
      </motion.span>

      <motion.h1 className="mt-4 font-display text-7xl text-bone md:text-[9rem]" {...rise(0.08)}>
        MORF
      </motion.h1>
      <motion.span className="eyebrow mt-2 text-signal" {...rise(0.16)}>
        Mobile Reconnaissance Framework
      </motion.span>

      {/* Thesis line with the signature redaction reveal. */}
      <motion.p
        className="mt-10 max-w-xl font-sans text-xl leading-relaxed text-bone-dim md:text-2xl"
        {...rise(0.28)}
      >
        Mobile apps ship with{' '}
        <span
          className={`redaction align-baseline font-mono ${revealed ? 'revealed' : ''}`}
          aria-label="hardcoded secrets"
        >
          AKIA…SECRET
        </span>{' '}
        hardcoded inside. MORF finds them before attackers do.
      </motion.p>

      {/* How it works — informative, quiet. */}
      <motion.ol className="mt-10 flex flex-wrap items-center justify-center gap-x-8 gap-y-3" {...rise(0.4)}>
        {STEPS.map((s) => (
          <li key={s.n} className="flex items-center gap-2 text-left">
            <span className="font-display text-lg text-signal">{s.n}</span>
            <span className="flex flex-col">
              <span className="font-sans text-sm font-semibold text-bone">{s.label}</span>
              <span className="font-mono text-[0.68rem] text-bone-dim">{s.detail}</span>
            </span>
          </li>
        ))}
      </motion.ol>

      <motion.div className="mt-12 flex flex-wrap items-center justify-center gap-3" {...rise(0.52)}>
        <Button size="lg" onClick={() => setScreen('upload')}>
          Analyze an app <ArrowRight className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="lg" onClick={() => setScreen('patterns')}>
          <ScrollText className="h-4 w-4" /> Detection rules
        </Button>
      </motion.div>

      <span className="pointer-events-none absolute bottom-6 font-mono text-[0.6rem] uppercase tracking-[0.3em] text-bone-dim/60">
        v1.0.0 · Static analysis · Android &amp; iOS
      </span>
    </div>
  )
}
