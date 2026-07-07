import { useRef, useState } from 'react'
import { motion, useReducedMotion, type Variants } from 'framer-motion'
import { useScan } from '@/store/scanStore'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'

export function Upload() {
  const { selectedPlatform, setSelectedPlatform, processFile } = useScan()
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const reduceMotion = useReducedMotion()

  const ext = selectedPlatform === 'ios' ? '.ipa' : '.apk'
  const platformName = selectedPlatform === 'ios' ? 'iOS' : 'Android'

  const handle = (file?: File | null) => {
    if (!file) return
    if (!file.name.toLowerCase().endsWith(ext)) {
      const got = file.name.includes('.') ? file.name.slice(file.name.lastIndexOf('.')) : 'that file'
      setError(
        `That's a ${got} file, but ${platformName} analysis needs a ${ext}. Switch the platform above, or drop a ${ext} instead.`,
      )
      return
    }
    setError(null)
    processFile(file)
  }

  const openPicker = () => inputRef.current?.click()

  // ONE tasteful entrance: stagger the intake blocks in. No motion when reduced.
  const container: Variants = reduceMotion
    ? { hidden: {}, show: {} }
    : { hidden: {}, show: { transition: { staggerChildren: 0.08, delayChildren: 0.04 } } }
  const item: Variants = reduceMotion
    ? { hidden: { opacity: 1 }, show: { opacity: 1 } }
    : {
        hidden: { opacity: 0, y: 12 },
        show: { opacity: 1, y: 0, transition: { duration: 0.4, ease: [0.22, 1, 0.36, 1] } },
      }

  return (
    <motion.div
      variants={container}
      initial="hidden"
      animate="show"
      className="mx-auto flex min-h-[calc(100vh-4rem)] max-w-3xl flex-col justify-center gap-8 px-6 py-16"
    >
      <motion.div variants={item}>
        <span className="eyebrow">Intake</span>
        <h1 className="font-display text-5xl text-bone">Open a case file</h1>
        <p className="mt-3 max-w-xl font-sans text-bone-dim">
          Hand over a mobile app package and MORF combs it for hardcoded secrets, exposed
          components, and telling metadata.
        </p>
      </motion.div>

      {/* Platform choice — explained, with the accepted extension shown. */}
      <motion.div variants={item} className="flex flex-col gap-2">
        <span className="font-mono text-xs uppercase tracking-widest text-bone-dim">
          What are we looking at?
        </span>
        <div role="tablist" aria-label="Target platform" className="flex flex-wrap gap-2 font-mono text-sm">
          {(
            [
              { id: 'android', label: 'Android', accepts: '.apk' },
              { id: 'ios', label: 'iOS', accepts: '.ipa' },
            ] as const
          ).map((p) => {
            const active = selectedPlatform === p.id
            return (
              <button
                key={p.id}
                role="tab"
                aria-selected={active}
                onClick={() => {
                  setSelectedPlatform(p.id)
                  setError(null)
                }}
                className={cn(
                  'flex items-baseline gap-2 rounded border px-4 py-2 uppercase tracking-wider transition-colors',
                  active
                    ? 'border-signal text-signal'
                    : 'border-ink-700 text-bone-dim hover:border-bone-dim hover:text-bone',
                )}
              >
                <span>{p.label}</span>
                <span className={cn('lowercase tracking-normal', active ? 'text-signal/70' : 'text-bone-dim/60')}>
                  {p.accepts}
                </span>
              </button>
            )
          })}
        </div>
      </motion.div>

      {/* Dropzone — obviously interactive, keyboard reachable. */}
      <motion.div variants={item}>
        <div
          role="button"
          tabIndex={0}
          aria-label={`Upload a ${ext} file for ${platformName} analysis — drag and drop, or activate to browse`}
          onClick={openPicker}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              openPicker()
            }
          }}
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
            'dossier group flex min-h-64 cursor-pointer flex-col items-center justify-center gap-3 rounded border-2 border-dashed p-10 text-center transition-colors',
            dragging
              ? 'border-signal bg-signal/5'
              : error
                ? 'border-oxblood/60 hover:border-oxblood'
                : 'border-bone-dim/40 hover:border-signal hover:bg-signal/[0.03]',
          )}
        >
          <span className="font-display text-2xl text-bone">
            Drag a {ext} here, or click to browse
          </span>
          <span className="font-mono text-xs uppercase tracking-widest text-bone-dim">
            {platformName} · accepts {ext}
          </span>
          <Button
            variant="outline"
            size="sm"
            className="mt-2 pointer-events-none"
            tabIndex={-1}
            aria-hidden="true"
          >
            Choose file
          </Button>
          <input
            ref={inputRef}
            type="file"
            accept=".apk,.ipa"
            className="hidden"
            onChange={(e) => {
              handle(e.target.files?.[0])
              e.target.value = ''
            }}
          />
        </div>

        {/* Inline extension-mismatch error — dossier voice: what's wrong + how to fix. */}
        {error && (
          <p role="alert" className="mt-3 font-mono text-sm text-oxblood">
            {error}
          </p>
        )}
      </motion.div>

      {/* What happens next / analyzed locally. */}
      <motion.div variants={item} className="dossier rounded border border-ink-700 p-4">
        <span className="font-mono text-xs uppercase tracking-widest text-bone-dim">
          What happens next
        </span>
        <p className="mt-2 font-sans text-sm text-bone-dim">
          We unpack the archive, parse its manifest and metadata, then run every detection rule
          across the decompiled sources. Your file is analyzed on this machine — nothing about the
          app leaves your setup.
        </p>
      </motion.div>
    </motion.div>
  )
}
