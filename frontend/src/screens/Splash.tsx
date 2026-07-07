import { useEffect, useMemo, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { useScan } from '@/store/scanStore'
import morfLogo from '@/assets/morf.png'

// Cinematic boot: the mark under a radar sweep + breathing glow on a particle
// field, the wordmark decoding in, and a slim progress line to the handoff.
// A full-screen overlay (z-60) so nothing bleeds through during the exit.
// Auto-flows into upload; a click or any key skips.
const HOLD_MS = 3000
const HOLD_MS_REDUCED = 700
const GLYPHS = 'ABCDEFGHKLMNPRSTUVWXYZ#%$&/<>'

function useScramble(target: string, enabled: boolean) {
  const [out, setOut] = useState(enabled ? '' : target)
  useEffect(() => {
    if (!enabled) {
      setOut(target)
      return
    }
    let frame = 0
    const id = setInterval(() => {
      frame++
      const locked = Math.floor(frame / 3)
      let s = ''
      for (let i = 0; i < target.length; i++) {
        s += i < locked ? target[i] : GLYPHS[Math.floor(Math.random() * GLYPHS.length)]
      }
      setOut(s)
      if (locked >= target.length) {
        setOut(target)
        clearInterval(id)
      }
    }, 55)
    return () => clearInterval(id)
  }, [target, enabled])
  return out
}

export function Splash() {
  const { setScreen } = useScan()
  const reduce = useReducedMotion()
  const [leaving, setLeaving] = useState(false)
  const wordmark = useScramble('MORF', !reduce)

  const go = () => setScreen('upload')

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

  // Deterministic-enough particle field (generated once).
  const particles = useMemo(
    () =>
      Array.from({ length: 26 }, (_, i) => ({
        id: i,
        left: `${Math.random() * 100}%`,
        top: `${Math.random() * 100}%`,
        size: `${3 + Math.random() * 5}px`,
        delay: `${Math.random() * 3}s`,
        cyan: Math.random() > 0.5,
      })),
    [],
  )

  const ease = [0.2, 0.8, 0.2, 1] as const

  return (
    <motion.div
      onClick={() => {
        setLeaving(true)
        go()
      }}
      role="button"
      tabIndex={-1}
      aria-label="Enter MORF"
      className="fixed inset-0 z-[60] flex cursor-pointer flex-col items-center justify-center overflow-hidden bg-base"
      animate={leaving && !reduce ? { opacity: 0 } : { opacity: 1 }}
      transition={{ duration: 0.45, ease }}
    >
      {/* Aurora + vignette. */}
      {!reduce && (
        <>
          <div className="pointer-events-none absolute left-1/2 top-1/2 h-[36rem] w-[36rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-indigo/15 blur-[140px] animate-glow-pulse" />
          <div className="pointer-events-none absolute bottom-8 right-1/4 h-72 w-72 rounded-full bg-cyan/10 blur-[120px] animate-glow-pulse" />
          {/* Particle field. */}
          {particles.map((p) => (
            <span
              key={p.id}
              className={`pointer-events-none absolute rounded-full animate-particle ${
                p.cyan ? 'bg-cyan/70' : 'bg-indigo-hi/70'
              }`}
              style={{ left: p.left, top: p.top, width: p.size, height: p.size, animationDelay: p.delay }}
            />
          ))}
        </>
      )}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(120%_120%_at_50%_50%,transparent_40%,rgba(10,14,23,0.85)_100%)]" />

      <motion.div
        className="relative z-10 flex flex-col items-center"
        animate={leaving && !reduce ? { scale: 1.05 } : { scale: 1 }}
        transition={{ duration: 0.45, ease }}
      >
        {/* Logo: radar rings + sweep + breathing glow. */}
        <motion.div
          className="relative grid h-44 w-44 place-items-center md:h-52 md:w-52"
          initial={reduce ? {} : { opacity: 0, scale: 0.85 }}
          animate={reduce ? {} : { opacity: 1, scale: 1 }}
          transition={{ duration: 0.7, ease }}
        >
          {!reduce && (
            <>
              <span className="absolute inset-4 rounded-full border border-indigo/30 animate-ping-ring" />
              <span
                className="absolute inset-4 rounded-full border border-cyan/25 animate-ping-ring"
                style={{ animationDelay: '1.5s' }}
              />
            </>
          )}
          <div className="pointer-events-none absolute inset-8 -z-10 rounded-full bg-indigo/25 blur-3xl" />
          <div className="relative h-32 w-32 overflow-hidden md:h-36 md:w-36">
            <img
              src={morfLogo}
              alt="MORF"
              className={`h-full w-full object-contain ${reduce ? '' : 'animate-breathe'}`}
            />
            {!reduce && (
              <div className="pointer-events-none absolute inset-x-0 top-0 h-1/2 animate-scan-sweep bg-gradient-to-b from-transparent via-cyan/50 to-transparent mix-blend-screen" />
            )}
          </div>
        </motion.div>

        {/* Wordmark (decodes in) + tagline. */}
        <h1 className="mt-8 font-display text-6xl font-bold leading-none tracking-tight md:text-8xl">
          <span className="gradient-text tabular-nums">{wordmark}</span>
        </h1>
        <motion.p
          className="mt-3 max-w-md font-sans text-sm text-txt-muted md:text-base"
          initial={reduce ? {} : { opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.5, ease }}
        >
          <span className="text-txt">Mobile Reconnaissance Framework</span>
        </motion.p>
      </motion.div>

      {/* Progress + status. */}
      <div className="absolute bottom-16 z-10 flex flex-col items-center gap-3">
        <div className="h-[3px] w-52 overflow-hidden rounded-full bg-line">
          <motion.div
            className="h-full bg-gradient-to-r from-indigo to-cyan"
            initial={{ width: reduce ? '100%' : '0%' }}
            animate={{ width: '100%' }}
            transition={{ duration: (reduce ? HOLD_MS_REDUCED : HOLD_MS) / 1000, ease: 'linear' }}
          />
        </div>
        <div className="flex items-center gap-2">
          {!reduce &&
            [0, 0.2, 0.4].map((d) => (
              <span
                key={d}
                className="h-1.5 w-1.5 rounded-full bg-cyan animate-dot-pulse"
                style={{ animationDelay: `${d}s` }}
              />
            ))}
          <span className="eyebrow ml-1 text-txt-dim">Initializing reconnaissance</span>
        </div>
      </div>

      <span className="pointer-events-none absolute bottom-6 z-10 font-mono text-[0.6rem] uppercase tracking-[0.28em] text-txt-dim">
        Click anywhere to skip · Android &amp; iOS
      </span>
    </motion.div>
  )
}
