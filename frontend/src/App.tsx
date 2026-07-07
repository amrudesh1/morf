import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { X } from 'lucide-react'
import { ScanStoreProvider, useScan } from '@/store/scanStore'
import { Splash } from '@/screens/Splash'
import { Upload } from '@/screens/Upload'
import { Processing } from '@/screens/Processing'
import { Results } from '@/screens/Results'
import { PatternManagement } from '@/screens/PatternManagement'
import type { Screen } from '@/types'

const SCREENS: Record<Screen, React.ComponentType> = {
  splash: Splash,
  upload: Upload,
  processing: Processing,
  results: Results,
  patterns: PatternManagement,
}

function Shell() {
  const { currentScreen, error, clearError } = useScan()
  const reduce = useReducedMotion()
  const Current = SCREENS[currentScreen]

  return (
    <div className="relative min-h-screen overflow-x-hidden bg-ink text-bone">
      <AnimatePresence>
        {error && (
          <motion.div
            role="alert"
            initial={{ y: -24, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -24, opacity: 0 }}
            className="fixed inset-x-0 top-0 z-50 flex items-start justify-between gap-4 border-b border-oxblood bg-ink-900/95 px-4 py-3 backdrop-blur"
          >
            <div className="flex flex-col gap-1">
              <span className="eyebrow text-oxblood">Scan interrupted</span>
              <span className="font-mono text-sm text-bone">{error}</span>
            </div>
            <button
              onClick={clearError}
              aria-label="Dismiss"
              className="text-bone-dim transition-colors hover:text-signal focus-visible:text-signal"
            >
              <X className="h-5 w-5" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence mode="wait">
        <motion.div
          key={currentScreen}
          initial={reduce ? false : { opacity: 0, x: 24 }}
          animate={{ opacity: 1, x: 0 }}
          exit={reduce ? { opacity: 0 } : { opacity: 0, x: -24 }}
          transition={{ duration: 0.3, ease: 'easeOut' }}
          className="min-h-screen"
        >
          <Current />
        </motion.div>
      </AnimatePresence>
    </div>
  )
}

export function App() {
  return (
    <ScanStoreProvider>
      <Shell />
    </ScanStoreProvider>
  )
}
