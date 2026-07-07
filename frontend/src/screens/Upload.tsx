import { useRef, useState } from 'react'
import { motion, useReducedMotion, type Variants } from 'framer-motion'
import { UploadCloud, ShieldCheck, Smartphone, Apple } from 'lucide-react'
import { useScan } from '@/store/scanStore'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'
import type { Platform } from '@/types'

// One dropzone for both platforms — the extension tells us everything, so there
// is no platform to pick. .apk → Android, .ipa → iOS, anything else is rejected.
function detectPlatform(name: string): Platform | null {
  const n = name.toLowerCase()
  if (n.endsWith('.apk')) return 'android'
  if (n.endsWith('.ipa')) return 'ios'
  return null
}

export function Upload() {
  const { setSelectedPlatform, processFile } = useScan()
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const reduceMotion = useReducedMotion()

  const handle = (file?: File | null) => {
    if (!file) return
    const platform = detectPlatform(file.name)
    if (!platform) {
      const got = file.name.includes('.') ? file.name.slice(file.name.lastIndexOf('.')) : 'that file'
      setError(`MORF reads Android .apk and iOS .ipa packages — ${got} isn't one. Drop one of those.`)
      return
    }
    setError(null)
    setSelectedPlatform(platform) // keep store in sync for the processing screen
    processFile(file)
  }

  const openPicker = () => inputRef.current?.click()

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
        <h1 className="mt-2 font-display text-5xl font-bold tracking-tight text-txt">
          Every build hides <span className="gradient-text">something</span>.
        </h1>
        <p className="mt-3 max-w-xl font-sans text-txt-muted">
          Drop a mobile app package and MORF combs it for hardcoded secrets, exposed components,
          and telling metadata — in seconds.
        </p>
      </motion.div>

      {/* Dropzone — one window for both platforms; the extension picks the lane. */}
      <motion.div variants={item}>
        <div
          role="button"
          tabIndex={0}
          aria-label="Upload an .apk or .ipa file — drag and drop, or activate to browse"
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
            'card group flex min-h-72 cursor-pointer flex-col items-center justify-center gap-4 border-2 border-dashed p-10 text-center transition-colors',
            dragging
              ? 'border-indigo bg-indigo/[0.06]'
              : error
                ? 'border-sev-high/50 hover:border-sev-high'
                : 'border-line-hi hover:border-indigo hover:bg-indigo/[0.03]',
          )}
        >
          <span
            className={cn(
              'flex h-14 w-14 items-center justify-center rounded-2xl border transition-colors',
              dragging
                ? 'border-indigo/50 bg-indigo/10 text-indigo-hi'
                : 'border-line bg-surface-hi text-txt-muted group-hover:border-indigo/40 group-hover:text-indigo-hi',
            )}
          >
            <UploadCloud className="h-6 w-6" />
          </span>
          <span className="font-display text-2xl font-semibold tracking-tight text-txt">
            {dragging ? 'Drop it — we’ll take it from here' : 'Drag your build here, or click to browse'}
          </span>

          {/* Supported formats — informational, not a choice to make. */}
          <div className="flex items-center gap-2">
            <span className="chip">
              <Smartphone className="h-3 w-3" /> Android .apk
            </span>
            <span className="chip">
              <Apple className="h-3 w-3" /> iOS .ipa
            </span>
          </div>

          <Button
            variant="outline"
            size="sm"
            className="mt-1 pointer-events-none"
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

        {/* Inline error — what's wrong + how to fix. */}
        {error && (
          <p role="alert" className="mt-3 font-mono text-sm text-sev-high">
            {error}
          </p>
        )}
      </motion.div>

      {/* What happens next / analyzed locally. */}
      <motion.div variants={item} className="card card-hover p-5">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-cyan" />
          <span className="eyebrow">What happens next</span>
        </div>
        <p className="mt-2.5 font-sans text-sm text-txt-muted">
          We unpack the archive, parse its manifest and metadata, then run every detection rule
          across the decompiled sources. Your file is analyzed on this machine — nothing about the
          app leaves your setup.
        </p>
      </motion.div>
    </motion.div>
  )
}
