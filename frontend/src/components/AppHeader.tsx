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
          className="h-8 w-8 object-contain drop-shadow-[0_2px_10px_rgba(99,102,241,0.45)]"
        />
        <span className="flex flex-col leading-none">
          <span className="font-display text-lg font-bold tracking-tight text-txt transition-colors group-hover:text-indigo-hi">
            MORF
          </span>
          <span className="hidden text-[0.55rem] uppercase tracking-[0.24em] text-txt-dim sm:inline">
            Mobile Reconnaissance Framework
          </span>
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
