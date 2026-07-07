import { FileSearch, ScrollText, RotateCcw } from 'lucide-react'
import { useScan } from '@/store/scanStore'
import { Button } from '@/components/ui/Button'

// Persistent top bar so users are always oriented and can always get back.
// Hidden on splash (see App shell). The wordmark is the home affordance.
export function AppHeader() {
  const { currentScreen, setScreen, resetScan } = useScan()
  const onPatterns = currentScreen === 'patterns'

  return (
    <header className="sticky top-0 z-40 flex items-center justify-between border-b border-ink-700 bg-ink/85 px-4 py-3 backdrop-blur md:px-8">
      <button
        onClick={() => (onPatterns ? setScreen('upload') : resetScan())}
        className="group flex items-baseline gap-2"
        aria-label="MORF home"
      >
        <span className="font-display text-2xl leading-none text-bone transition-colors group-hover:text-signal">
          MORF
        </span>
        <span className="hidden text-[0.6rem] uppercase tracking-[0.28em] text-bone-dim sm:inline">
          Mobile Reconnaissance Framework
        </span>
      </button>

      <nav className="flex items-center gap-2">
        {onPatterns ? (
          <Button variant="ghost" size="sm" onClick={() => setScreen('upload')}>
            <FileSearch className="h-3.5 w-3.5" /> Back to scan
          </Button>
        ) : (
          <>
            <Button variant="ghost" size="sm" onClick={() => setScreen('patterns')}>
              <ScrollText className="h-3.5 w-3.5" /> Detection rules
            </Button>
            <Button variant="ghost" size="sm" onClick={resetScan}>
              <RotateCcw className="h-3.5 w-3.5" /> New scan
            </Button>
          </>
        )}
      </nav>
    </header>
  )
}
