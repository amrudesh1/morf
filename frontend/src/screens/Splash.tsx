import { useEffect } from 'react'
import { useScan } from '@/store/scanStore'

export function Splash() {
  const { setScreen } = useScan()
  useEffect(() => {
    const t = setTimeout(() => setScreen('upload'), 2600)
    return () => clearTimeout(t)
  }, [setScreen])

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 px-6 text-center">
      <span className="eyebrow">Case file · Classified</span>
      <h1 className="font-display text-7xl text-bone md:text-9xl">MORF</h1>
      <span className="eyebrow text-signal">Mobile Reconnaissance Framework</span>
      <button
        onClick={() => setScreen('upload')}
        className="mt-4 font-mono text-xs uppercase tracking-widest text-bone-dim underline-offset-4 hover:text-signal hover:underline"
      >
        Open case file →
      </button>
    </div>
  )
}
