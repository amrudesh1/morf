import { useRef, useState } from 'react'
import { useScan } from '@/store/scanStore'
import { cn } from '@/lib/cn'

export function Upload() {
  const { selectedPlatform, setSelectedPlatform, processFile, setScreen } = useScan()
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const ext = selectedPlatform === 'ios' ? '.ipa' : '.apk'

  const handle = (file?: File | null) => {
    if (!file) return
    if (!file.name.toLowerCase().endsWith(ext)) {
      alert(`Select a ${ext} file for ${selectedPlatform === 'ios' ? 'iOS' : 'Android'} analysis.`)
      return
    }
    processFile(file)
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-3xl flex-col gap-8 px-6 py-16">
      <div className="flex items-center justify-between">
        <span className="font-display text-3xl">MORF</span>
        <button
          onClick={() => setScreen('patterns')}
          className="font-mono text-xs uppercase tracking-widest text-bone-dim hover:text-signal"
        >
          Detection rules
        </button>
      </div>

      <div>
        <span className="eyebrow">Intake</span>
        <h1 className="font-display text-5xl text-bone">Open a case file</h1>
      </div>

      <div role="tablist" className="flex gap-2 font-mono text-sm">
        {(['android', 'ios'] as const).map((p) => (
          <button
            key={p}
            role="tab"
            aria-selected={selectedPlatform === p}
            onClick={() => setSelectedPlatform(p)}
            className={cn(
              'rounded border px-4 py-2 uppercase tracking-wider transition-colors',
              selectedPlatform === p
                ? 'border-signal text-signal'
                : 'border-ink-700 text-bone-dim hover:text-bone',
            )}
          >
            {p === 'ios' ? 'iOS · .ipa' : 'Android · .apk'}
          </button>
        ))}
      </div>

      <button
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragging(false)
          handle(e.dataTransfer.files?.[0])
        }}
        className={cn(
          'flex min-h-64 flex-col items-center justify-center gap-3 rounded border-2 border-dashed p-10 text-center transition-colors',
          dragging ? 'border-signal bg-signal/5' : 'border-bone-dim/50 hover:border-signal',
        )}
      >
        <span className="font-display text-2xl text-bone">Drop a {ext} to analyze</span>
        <span className="font-mono text-xs text-bone-dim">or click to choose · accepts .apk · .ipa</span>
        <input
          ref={inputRef}
          type="file"
          accept=".apk,.ipa"
          className="hidden"
          onChange={(e) => handle(e.target.files?.[0])}
        />
      </button>
    </div>
  )
}
