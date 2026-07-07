import { FileSearch, ScrollText, RotateCcw } from 'lucide-react'
import { useScan } from '@/store/scanStore'
import { Button } from '@/components/ui/Button'
import morfLogo from '@/assets/morf.png'

// Persistent top bar so users are always oriented and can always get back.
// Hidden on splash (see App shell). The wordmark is the home affordance.
export function AppHeader() {
  const { currentScreen, setScreen, resetScan } = useScan()
  const onPatterns = currentScreen === 'patterns'

  return (
    <header className="sticky top-0 z-40 flex items-center justify-between border-b border-line bg-base/80 px-4 py-3 backdrop-blur-xl md:px-8">
      <button
        onClick={() => (onPatterns ? setScreen('upload') : resetScan())}
        className="group flex items-center gap-2.5"
        aria-label="MORF home"
      >
        <img
          src={morfLogo}
          alt=""
          aria-hidden="true"
          className="h-7 w-7 object-contain opacity-90 transition group-hover:opacity-100"
        />
        <span className="font-display text-lg font-bold tracking-tight text-txt transition-colors group-hover:text-indigo-hi">
          MORF
        </span>
        <span className="hidden h-4 w-px bg-line md:inline-block" />
        <span className="hidden text-[0.6rem] uppercase tracking-[0.22em] text-txt-dim md:inline">
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
