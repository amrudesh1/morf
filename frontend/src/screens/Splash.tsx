import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { useScan } from '@/store/scanStore'
import morfLogo from '@/assets/morf.png'

// A brief, cinematic brand moment that AUTO-FLOWS into the upload screen. No CTAs
// (the handoff is automatic) — just the mark under a scanning sweep, the wordmark,
// and a slim progress line. A click or any key skips ahead.
const HOLD_MS = 2800
const HOLD_MS_REDUCED = 800

export function Splash() {
  const { setScreen } = useScan()
  const reduce = useReducedMotion()
  const [leaving, setLeaving] = useState(false)

  const go = () => setScreen('upload')

  // Auto-advance, and let a click / any key skip.
  useEffect(() => {
    const id = setTimeout(go, reduce ? HOLD_MS_REDUCED : HOLD_MS)
    const onKey = () => go()
    window.addEventListener('keydown', onKey)
    return () => {
      clearTimeout(id)
      window.removeEventListener('keydown', onKey)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reduce])

  const ease = [0.2, 0.8, 0.2, 1] as const

  return (
    <div
      onClick={() => {
        setLeaving(true)
        go()
      }}
      role="button"
      tabIndex={-1}
      aria-label="Enter MORF"
      className="relative flex min-h-screen cursor-pointer flex-col items-center justify-center overflow-hidden px-6 text-center"
    >
      {/* Ambient spotlight. */}
      {!reduce && (
        <>
          <div className="pointer-events-none absolute left-1/2 top-1/3 h-[32rem] w-[32rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-indigo/15 blur-[130px] animate-glow-pulse" />
          <div className="pointer-events-none absolute bottom-0 right-1/4 h-72 w-72 rounded-full bg-cyan/10 blur-[120px] animate-glow-pulse" />
        </>
      )}

      <motion.div
        className="flex flex-col items-center"
        animate={leaving && !reduce ? { scale: 1.04, opacity: 0 } : { scale: 1, opacity: 1 }}
        transition={{ duration: 0.4, ease }}
      >
        {/* Logo under a scanning sweep. */}
        <motion.div
          className="relative"
          initial={reduce ? {} : { opacity: 0, scale: 0.9 }}
          animate={reduce ? {} : { opacity: 1, scale: 1 }}
          transition={{ duration: 0.7, ease }}
        >
          <div className="pointer-events-none absolute inset-0 -z-10 rounded-full bg-indigo/25 blur-3xl" />
          <img
            src={morfLogo}
            alt="MORF"
            className="h-36 w-36 object-contain drop-shadow-[0_10px_45px_rgba(99,102,241,0.55)] md:h-44 md:w-44"
          />
          {!reduce && (
            <div className="pointer-events-none absolute inset-x-0 top-0 h-1/3 animate-scan-sweep bg-gradient-to-b from-transparent via-cyan/40 to-transparent mix-blend-screen" />
          )}
        </motion.div>

        {/* Wordmark + tagline. */}
        <motion.h1
          className="mt-8 font-display text-6xl font-bold leading-none tracking-tight md:text-8xl"
          initial={reduce ? {} : { opacity: 0, y: 14 }}
          animate={reduce ? {} : { opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.15, ease }}
        >
          <span className="gradient-text">MORF</span>
        </motion.h1>
        <motion.p
          className="mt-3 max-w-md font-sans text-sm text-txt-muted md:text-base"
          initial={reduce ? {} : { opacity: 0 }}
          animate={reduce ? {} : { opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.35, ease }}
        >
          <span className="text-txt">Mobile Reconnaissance Framework</span>
          <span className="mx-2 text-txt-dim">·</span>
          finds hardcoded secrets before attackers do
        </motion.p>
      </motion.div>

      {/* Slim progress line to the handoff. */}
      <div className="absolute bottom-16 flex flex-col items-center gap-3">
        <div className="h-[3px] w-48 overflow-hidden rounded-full bg-line">
          <motion.div
            className="h-full bg-gradient-to-r from-indigo to-cyan"
            initial={{ width: reduce ? '100%' : '0%' }}
            animate={{ width: '100%' }}
            transition={{ duration: (reduce ? HOLD_MS_REDUCED : HOLD_MS) / 1000, ease: 'linear' }}
          />
        </div>
        <span className="eyebrow text-txt-dim">Initializing reconnaissance</span>
      </div>

      <span className="pointer-events-none absolute bottom-6 font-mono text-[0.6rem] uppercase tracking-[0.28em] text-txt-dim">
        Click anywhere to skip · Android &amp; iOS
      </span>
    </div>
  )
}
