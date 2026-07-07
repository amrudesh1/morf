import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { X } from 'lucide-react'
import { ScanStoreProvider, useScan } from '@/store/scanStore'
import { AppHeader } from '@/components/AppHeader'
import { AuroraBackground } from '@/components/AuroraBackground'
import { Splash } from '@/screens/Splash'
import { Upload } from '@/screens/Upload'
import { Processing } from '@/screens/Processing'
import { Results } from '@/screens/Results'
import { PatternManagement } from '@/screens/PatternManagement'
import type { Screen } from '@/types'

const SCREENS: Record<Exclude<Screen, 'splash'>, React.ComponentType> = {
  upload: Upload,
  processing: Processing,
  results: Results,
  patterns: PatternManagement,
}

function Shell() {
  const { currentScreen, error, clearError } = useScan()
  const reduce = useReducedMotion()
  const isSplash = currentScreen === 'splash'
  const Current = currentScreen === 'splash' ? Upload : SCREENS[currentScreen]

  return (
    <div className="relative min-h-screen overflow-x-hidden bg-base text-txt">
      {/* Shared ambient aurora — ties every screen to the splash. */}
      <div className="fixed inset-0 -z-10">
        <AuroraBackground />
      </div>

      <AnimatePresence>
        {error && (
          <motion.div
            role="alert"
            initial={{ y: -24, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -24, opacity: 0 }}
            className="fixed inset-x-0 top-0 z-50 flex items-start justify-between gap-4 border-b border-sev-high/50 bg-sev-high/10 px-4 py-3 backdrop-blur-xl"
          >
            <div className="flex flex-col gap-1">
              <span className="eyebrow text-sev-high">Scan interrupted</span>
              <span className="font-mono text-sm text-txt">{error}</span>
            </div>
            <button
              onClick={clearError}
              aria-label="Dismiss"
              className="text-txt-muted transition-colors hover:text-txt focus-visible:text-txt"
            >
              <X className="h-5 w-5" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {!isSplash && <AppHeader />}

      {/* Main screen router (splash excluded — it's a top-level overlay below). */}
      <AnimatePresence mode="wait">
        <motion.div
          key={isSplash ? 'upload' : currentScreen}
          initial={reduce ? false : { opacity: 0, x: 24 }}
          animate={{ opacity: 1, x: 0 }}
          exit={reduce ? { opacity: 0 } : { opacity: 0, x: -24 }}
          transition={{ duration: 0.3, ease: 'easeOut' }}
          className="min-h-screen"
        >
          <Current />
        </motion.div>
      </AnimatePresence>

      {/* Splash: a true viewport overlay (not inside the transformed router, so
          it genuinely covers the header). Fades out on exit to reveal the app. */}
      <AnimatePresence>{isSplash && <Splash key="splash" />}</AnimatePresence>
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
