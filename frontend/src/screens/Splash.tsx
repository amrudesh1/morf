import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { ArrowRight, ScrollText, ShieldAlert } from 'lucide-react'
import { useScan } from '@/store/scanStore'
import { Button } from '@/components/ui/Button'
import morfLogo from '@/assets/morf.png'

// Intro hero that AUTO-FLOWS into the upload screen after a beat. It states what
// MORF does, dramatizes the thesis (a frosted "leaked" key sharpens on a loop),
// and shows a progress bar counting down to the handoff. The CTA skips ahead.
const HOLD_MS = 3200
const HOLD_MS_REDUCED = 900

export function Splash() {
  const { setScreen } = useScan()
  const reduce = useReducedMotion()
  const [revealed, setRevealed] = useState(false)

  // Auto-advance into the workspace.
  useEffect(() => {
    const id = setTimeout(() => setScreen('upload'), reduce ? HOLD_MS_REDUCED : HOLD_MS)
    return () => clearTimeout(id)
  }, [reduce, setScreen])

  // Loop the frosted-secret reveal while we hold.
  useEffect(() => {
    if (reduce) {
      setRevealed(true)
      return
    }
    let on = false
    const id = setInterval(() => {
      on = !on
      setRevealed(on)
    }, 1500)
    return () => clearInterval(id)
  }, [reduce])

  const ease = [0.2, 0.8, 0.2, 1] as const
  const rise = (delay: number) =>
    reduce
      ? {}
      : { initial: { opacity: 0, y: 16 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.5, delay, ease } }

  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden px-6 text-center">
      {/* Ambient orbs. */}
      {!reduce && (
        <>
          <div className="pointer-events-none absolute -top-24 left-1/4 h-72 w-72 rounded-full bg-indigo/20 blur-[110px] animate-glow-pulse" />
          <div className="pointer-events-none absolute -bottom-24 right-1/4 h-72 w-72 rounded-full bg-cyan/15 blur-[120px] animate-glow-pulse" />
        </>
      )}

      {/* Original MORF logo. */}
      <motion.img
        src={morfLogo}
        alt="MORF"
        className="h-32 w-32 object-contain drop-shadow-[0_8px_40px_rgba(99,102,241,0.5)] md:h-40 md:w-40"
        initial={reduce ? {} : { opacity: 0, scale: 0.85 }}
        animate={reduce ? {} : { opacity: 1, scale: 1 }}
        transition={{ duration: 0.6, ease }}
      />

      <motion.div className="badge badge--indigo mt-6" {...rise(0.12)}>
        <ShieldAlert className="h-3.5 w-3.5" /> Static secret reconnaissance
      </motion.div>

      <motion.h1
        className="mt-5 font-display text-6xl font-bold leading-none tracking-tight md:text-8xl"
        {...rise(0.2)}
      >
        <span className="gradient-text">MORF</span>
      </motion.h1>
      <motion.span className="eyebrow mt-2 text-txt-muted" {...rise(0.28)}>
        Mobile Reconnaissance Framework
      </motion.span>

      <motion.p
        className="mt-8 max-w-xl font-sans text-lg leading-relaxed text-txt-muted md:text-xl"
        {...rise(0.26)}
      >
        Mobile apps ship with{' '}
        <span
          className={`reveal align-baseline ${revealed ? 'revealed' : ''}`}
          aria-label="hardcoded secrets"
        >
          AKIA…SECRET
        </span>{' '}
        hardcoded inside. MORF finds them before attackers do.
      </motion.p>

      <motion.div className="mt-10 flex flex-wrap items-center justify-center gap-3" {...rise(0.36)}>
        <Button size="lg" onClick={() => setScreen('upload')}>
          Enter workspace <ArrowRight className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="lg" onClick={() => setScreen('patterns')}>
          <ScrollText className="h-4 w-4" /> Detection rules
        </Button>
      </motion.div>

      {/* Countdown to auto-handoff. */}
      <div className="mt-14 flex flex-col items-center gap-2">
        <span className="eyebrow text-txt-dim">Opening intake…</span>
        <div className="h-0.5 w-40 overflow-hidden rounded-full bg-line">
          <motion.div
            className="h-full bg-gradient-to-r from-indigo to-cyan"
            initial={{ width: reduce ? '100%' : '0%' }}
            animate={{ width: '100%' }}
            transition={{ duration: (reduce ? HOLD_MS_REDUCED : HOLD_MS) / 1000, ease: 'linear' }}
          />
        </div>
      </div>

      <span className="pointer-events-none absolute bottom-6 font-mono text-[0.6rem] uppercase tracking-[0.28em] text-txt-dim">
        v1.0.0 · Static analysis · Android &amp; iOS
      </span>
    </div>
  )
}
