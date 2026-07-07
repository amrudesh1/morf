import type { ReactNode } from 'react'
import { motion, useReducedMotion } from 'framer-motion'

// Reveals its children as they scroll into view (fade + rise, once). Renders a
// plain div under prefers-reduced-motion. Used to bring long Results panels to
// life instead of showing everything static at once.
export function Reveal({
  children,
  delay = 0,
  className,
}: {
  children: ReactNode
  delay?: number
  className?: string
}) {
  const reduce = useReducedMotion()
  if (reduce) return <div className={className}>{children}</div>
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-10% 0px' }}
      transition={{ duration: 0.5, delay, ease: [0.2, 0.8, 0.2, 1] }}
    >
      {children}
    </motion.div>
  )
}
