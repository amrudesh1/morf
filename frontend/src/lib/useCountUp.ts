import { useEffect, useState } from 'react'
import { animate, useReducedMotion } from 'framer-motion'

// Animates an integer from 0 up to `target` over ~`durationMs`. Returns the
// target immediately under prefers-reduced-motion (no animation). Used for the
// Results "N exposed" headline so the count rolls up instead of snapping in.
export function useCountUp(target: number, durationMs = 650): number {
  const reduce = useReducedMotion()
  const [value, setValue] = useState(reduce ? target : 0)

  useEffect(() => {
    if (reduce) {
      setValue(target)
      return
    }
    const controls = animate(0, target, {
      duration: durationMs / 1000,
      ease: [0.2, 0.8, 0.2, 1],
      onUpdate: (v) => setValue(Math.round(v)),
    })
    return () => controls.stop()
  }, [target, durationMs, reduce])

  return value
}
