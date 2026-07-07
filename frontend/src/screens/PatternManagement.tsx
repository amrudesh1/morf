import { useEffect, useState, type ReactNode } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { motion, useReducedMotion } from 'framer-motion'
import { X } from 'lucide-react'
import { patternsApi } from '@/lib/api'
import type { Confidence, Pattern, PatternFile, PatternTestResponse } from '@/types'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'

const CONFIDENCES: Confidence[] = ['high', 'medium', 'low']

// Confidence → severity signal tokens (high→high, medium→med, low→low).
const sevDot: Record<Confidence, string> = {
  high: 'sev-dot--high',
  medium: 'sev-dot--med',
  low: 'sev-dot--low',
}

// --- Toast ------------------------------------------------------------------
function Toast({ message, onDone }: { message: string; onDone: () => void }) {
  const reduce = useReducedMotion()
  useEffect(() => {
    const t = setTimeout(onDone, 3000)
    return () => clearTimeout(t)
  }, [message, onDone])
  return (
    <motion.div
      role="status"
      aria-live="polite"
      initial={reduce ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      className="card fixed bottom-6 right-6 z-50 flex items-center gap-3 border-cyan/40 px-4 py-3 shadow-glow-cyan"
    >
      <span className="sev-dot sev-dot--low" />
      <span className="font-mono text-sm text-txt">{message}</span>
    </motion.div>
  )
}

// --- Modal shell ------------------------------------------------------------
function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
  title: string
  description: string
  children: ReactNode
}) {
  const reduce = useReducedMotion()
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-base/75 backdrop-blur-sm data-[state=open]:animate-in" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 w-[min(92vw,32rem)] -translate-x-1/2 -translate-y-1/2 focus:outline-none"
          asChild
        >
          <motion.div
            initial={reduce ? false : { opacity: 0, scale: 0.97, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            className="card rounded-xl p-6"
          >
            <Dialog.Title className="font-display text-2xl font-semibold text-txt">
              {title}
            </Dialog.Title>
            <Dialog.Description className="mt-1 font-mono text-xs text-txt-muted">
              {description}
            </Dialog.Description>
            <div className="mt-5">{children}</div>
          </motion.div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

// --- Shared form field styling ---------------------------------------------
const fieldCls =
  'w-full rounded-lg border border-line bg-surface px-3 py-2 font-sans text-sm text-txt placeholder:text-txt-dim focus:border-indigo focus:outline-none'
const labelCls = 'eyebrow mb-1.5 block'

function fieldError(msg: string) {
  return <p className="mt-1 font-mono text-xs text-sev-high">{msg}</p>
}

// --- Rule form (shared by Add + Edit) ---------------------------------------
interface RuleFormState {
  name: string
  regex: string
  confidence: Confidence
  enabled: boolean
}

function RuleForm({
  initial,
  lockName,
  submitLabel,
  busy,
  onSubmit,
  onCancel,
}: {
  initial: RuleFormState
  lockName: boolean
  submitLabel: string
  busy: boolean
  onSubmit: (p: Pattern) => void
  onCancel: () => void
}) {
  const [name, setName] = useState(initial.name)
  const [regex, setRegex] = useState(initial.regex)
  const [confidence, setConfidence] = useState<Confidence>(initial.confidence)
  const [enabled, setEnabled] = useState(initial.enabled)
  const [touched, setTouched] = useState(false)

  const nameInvalid = name.trim() === ''
  const regexInvalid = regex.trim() === ''

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setTouched(true)
    if (nameInvalid || regexInvalid) return
    onSubmit({ name: name.trim(), regex, confidence, enabled })
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div>
        <label className={labelCls} htmlFor="rule-name">
          Rule name
        </label>
        <input
          id="rule-name"
          className={cn(fieldCls, lockName && 'opacity-60')}
          value={name}
          disabled={lockName}
          onChange={(e) => setName(e.target.value)}
          placeholder="aws-secret-key"
          autoFocus={!lockName}
        />
        {touched && nameInvalid && fieldError('Give the rule a name.')}
      </div>

      <div>
        <label className={labelCls} htmlFor="rule-regex">
          Regex
        </label>
        <input
          id="rule-regex"
          className={cn(fieldCls, 'font-mono')}
          value={regex}
          onChange={(e) => setRegex(e.target.value)}
          placeholder="AKIA[0-9A-Z]{16}"
          autoFocus={lockName}
        />
        {touched && regexInvalid && fieldError('Add a regex to match against.')}
      </div>

      <div>
        <label className={labelCls} htmlFor="rule-confidence">
          Confidence
        </label>
        <select
          id="rule-confidence"
          className={fieldCls}
          value={confidence}
          onChange={(e) => setConfidence(e.target.value as Confidence)}
        >
          {CONFIDENCES.map((c) => (
            <option key={c} value={c}>
              {c[0].toUpperCase() + c.slice(1)}
            </option>
          ))}
        </select>
      </div>

      <label className="flex cursor-pointer items-center gap-2.5 font-sans text-sm text-txt">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => setEnabled(e.target.checked)}
          className="h-4 w-4 accent-indigo"
        />
        Enabled
      </label>

      <div className="flex justify-end gap-3 pt-2">
        <Button type="button" variant="ghost" size="sm" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" size="sm" disabled={busy}>
          {busy ? 'Saving…' : submitLabel}
        </Button>
      </div>
    </form>
  )
}

// ============================================================================
export function PatternManagement() {
  const reduce = useReducedMotion()
  const [files, setFiles] = useState<PatternFile[]>([])
  const [selectedName, setSelectedName] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  // Modal state
  const [showNewFile, setShowNewFile] = useState(false)
  const [showAdd, setShowAdd] = useState(false)
  const [editing, setEditing] = useState<Pattern | null>(null)
  const [testing, setTesting] = useState<Pattern | null>(null)
  const [confirmFileDelete, setConfirmFileDelete] = useState<string | null>(null)

  const selected = files.find((f) => f.filename === selectedName) ?? null

  const load = () => {
    setLoading(true)
    return patternsApi
      .list()
      .then((r) => {
        setFiles(r.files)
        setError(null)
        // Drop the selection if the file it pointed at is gone.
        setSelectedName((prev) => (prev && r.files.some((f) => f.filename === prev) ? prev : null))
      })
      .catch((e) => setError(e?.message ?? 'Could not load rule files. Try Reload.'))
      .finally(() => setLoading(false))
  }
  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Run a mutation, then reload and toast. Errors surface in the banner.
  const mutate = async (fn: () => Promise<unknown>, success: string) => {
    setBusy(true)
    setError(null)
    try {
      await fn()
      await load()
      setToast(success)
      return true
    } catch (e) {
      setError((e as Error)?.message ?? 'That action failed. Try again.')
      return false
    } finally {
      setBusy(false)
    }
  }

  // --- Handlers -------------------------------------------------------------
  const createFile = async (filename: string) => {
    const ok = await mutate(() => patternsApi.createFile(filename, []), `Created ${filename}.`)
    if (ok) {
      setShowNewFile(false)
      setSelectedName(filename)
    }
  }

  const deleteFile = async (filename: string) => {
    const ok = await mutate(() => patternsApi.deleteFile(filename), `Deleted ${filename}.`)
    if (ok) {
      setConfirmFileDelete(null)
      if (selectedName === filename) setSelectedName(null)
    }
  }

  const addRule = async (p: Pattern) => {
    if (!selected) return
    const ok = await mutate(() => patternsApi.addPattern(selected.filename, p), `Added rule ${p.name}.`)
    if (ok) setShowAdd(false)
  }

  const editRule = async (p: Pattern) => {
    if (!selected || !editing) return
    const ok = await mutate(
      () => patternsApi.updatePattern(selected.filename, editing.name, p),
      `Saved changes to ${p.name}.`,
    )
    if (ok) setEditing(null)
  }

  const deleteRule = async (name: string) => {
    if (!selected) return
    await mutate(() => patternsApi.deletePattern(selected.filename, name), `Deleted rule ${name}.`)
  }

  const toggleRule = async (p: Pattern) => {
    if (!selected) return
    await mutate(
      () => patternsApi.setEnabled(selected.filename, p.name, !p.enabled),
      `${p.name} is now ${p.enabled ? 'off' : 'on'}.`,
    )
  }

  return (
    <div className="mx-auto flex min-h-screen max-w-5xl flex-col gap-6 px-4 py-10 md:px-6">
      {/* Title + helper (global AppHeader owns the wordmark/nav) */}
      <header>
        <motion.h1
          initial={reduce ? false : { opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, ease: 'easeOut' }}
          className="font-display text-4xl font-semibold text-txt"
        >
          Detection rules ledger
        </motion.h1>
        <p className="mt-2 text-sm text-txt-muted">
          Manage the regex rules MORF uses to flag secrets. Pick a file on the left, then add, edit,
          test, or retire its rules.
        </p>
      </header>

      <div className="flex items-center gap-4">
        <Button variant="ghost" size="sm" onClick={() => void load()} disabled={loading}>
          {loading ? 'Reloading…' : 'Reload'}
        </Button>
      </div>

      {error && (
        <div
          role="alert"
          className="flex items-start justify-between gap-4 rounded-xl border border-sev-high/40 bg-sev-high/10 px-4 py-3"
        >
          <p className="font-mono text-sm text-sev-high">{error}</p>
          <button
            onClick={() => setError(null)}
            aria-label="Dismiss error"
            className="shrink-0 text-txt-muted transition-colors hover:text-txt"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-[1fr_2fr]">
        {/* Left: rule files */}
        <div className="card flex flex-col p-4">
          <div className="flex items-center justify-between">
            <span className="eyebrow">Rule files</span>
            <Button variant="outline" size="sm" onClick={() => setShowNewFile(true)}>
              New file
            </Button>
          </div>
          <ul className="mt-4 space-y-1.5">
            {files.map((f, i) => {
              const isActive = selectedName === f.filename
              return (
                <motion.li
                  key={f.filename}
                  className="group flex items-center gap-1"
                  initial={reduce ? false : { opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: Math.min(i * 0.03, 0.3), ease: [0.2, 0.8, 0.2, 1] }}
                >
                  <button
                    onClick={() => setSelectedName(f.filename)}
                    aria-current={isActive}
                    className={cn(
                      'flex w-full items-center justify-between rounded-lg border px-3 py-2 text-left font-mono text-sm transition-colors',
                      isActive
                        ? 'border-indigo/50 bg-indigo/10 text-indigo-hi'
                        : 'border-transparent text-txt-muted hover:border-line-hi hover:bg-surface-hi hover:text-txt',
                    )}
                  >
                    <span className="truncate">{f.filename}</span>
                    <span
                      className={cn(
                        'badge ml-2 shrink-0',
                        isActive ? 'badge--indigo' : 'badge--muted',
                      )}
                    >
                      {f.patterns.length} {f.patterns.length === 1 ? 'rule' : 'rules'}
                    </span>
                  </button>
                  <button
                    onClick={() => setConfirmFileDelete(f.filename)}
                    aria-label={`Delete file ${f.filename}`}
                    className="shrink-0 rounded-md p-1.5 text-txt-dim opacity-0 transition-opacity hover:text-sev-high focus-visible:opacity-100 group-hover:opacity-100"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </motion.li>
              )
            })}
            {files.length === 0 && !loading && (
              <li className="py-6 text-center font-mono text-xs text-txt-dim">
                No rule files yet — create one.
              </li>
            )}
            {files.length === 0 && loading && (
              <li className="py-6 text-center font-mono text-xs text-txt-muted">Loading files…</li>
            )}
          </ul>
        </div>

        {/* Right: selected file's rules */}
        <div className="card flex flex-col p-4">
          <div className="flex items-center justify-between">
            <span className="eyebrow">{selected ? selected.filename : 'Rules'}</span>
            {selected && (
              <Button variant="primary" size="sm" onClick={() => setShowAdd(true)}>
                Add rule
              </Button>
            )}
          </div>

          <div className="mt-4 flex flex-col">
            {!selected && (
              <p className="py-8 text-center font-mono text-sm text-txt-muted">
                Open a file to see its rules.
              </p>
            )}

            {selected && selected.patterns.length === 0 && (
              <p className="py-8 text-center font-mono text-sm text-txt-muted">
                No rules in this file yet — add one.
              </p>
            )}

            {selected?.patterns.map((p, i) => (
              <motion.div
                key={p.name}
                className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border-b border-line px-1 py-3 transition-colors last:border-b-0 hover:bg-surface-hi/40"
                initial={reduce ? false : { opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: Math.min(i * 0.03, 0.3), ease: [0.2, 0.8, 0.2, 1] }}
              >
                <span
                  className={cn('sev-dot', sevDot[p.confidence])}
                  aria-label={`${p.confidence} confidence`}
                  title={`${p.confidence} confidence`}
                />
                <span className="font-display text-sm font-semibold text-txt">{p.name}</span>
                <code className="min-w-0 max-w-[16rem] truncate rounded-md border border-line bg-surface-hi px-2 py-0.5 font-mono text-xs text-txt-muted">
                  {p.regex}
                </code>

                <button
                  onClick={() => void toggleRule(p)}
                  disabled={busy}
                  aria-label={p.enabled ? `Disable ${p.name}` : `Enable ${p.name}`}
                  className={cn(
                    'badge ml-auto transition-transform hover:scale-105 disabled:opacity-50',
                    p.enabled ? 'badge--cyan' : 'badge--muted',
                  )}
                >
                  {p.enabled ? 'On' : 'Off'}
                </button>

                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" onClick={() => setTesting(p)}>
                    Test
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => setEditing(p)}>
                    Edit
                  </Button>
                  <button
                    onClick={() => void deleteRule(p.name)}
                    disabled={busy}
                    aria-label={`Delete rule ${p.name}`}
                    className="px-2 py-1 font-mono text-xs uppercase tracking-widest text-txt-dim transition-colors hover:text-sev-high disabled:opacity-50"
                  >
                    Delete
                  </button>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>

      {/* --- Modals ------------------------------------------------------- */}

      {/* New rule file */}
      <Modal
        open={showNewFile}
        onOpenChange={setShowNewFile}
        title="New rule file"
        description="Create an empty file to hold a set of rules."
      >
        <NewFileForm busy={busy} onCancel={() => setShowNewFile(false)} onSubmit={createFile} />
      </Modal>

      {/* Add rule */}
      <Modal
        open={showAdd}
        onOpenChange={setShowAdd}
        title="Add rule"
        description={selected ? `New rule in ${selected.filename}.` : ''}
      >
        <RuleForm
          initial={{ name: '', regex: '', confidence: 'medium', enabled: true }}
          lockName={false}
          submitLabel="Add rule"
          busy={busy}
          onSubmit={addRule}
          onCancel={() => setShowAdd(false)}
        />
      </Modal>

      {/* Edit rule */}
      <Modal
        open={editing !== null}
        onOpenChange={(v) => !v && setEditing(null)}
        title="Edit rule"
        description={editing ? `Editing ${editing.name}. The rule name is fixed.` : ''}
      >
        {editing && (
          <RuleForm
            initial={{
              name: editing.name,
              regex: editing.regex,
              confidence: editing.confidence,
              enabled: editing.enabled,
            }}
            lockName
            submitLabel="Save changes"
            busy={busy}
            onSubmit={editRule}
            onCancel={() => setEditing(null)}
          />
        )}
      </Modal>

      {/* Test rule */}
      <Modal
        open={testing !== null}
        onOpenChange={(v) => !v && setTesting(null)}
        title="Run test"
        description={testing ? `Test ${testing.name} against sample text.` : ''}
      >
        {testing && selected && (
          <TestForm
            filename={selected.filename}
            patternName={testing.name}
            onClose={() => setTesting(null)}
            onError={setError}
          />
        )}
      </Modal>

      {/* Confirm file delete */}
      <Modal
        open={confirmFileDelete !== null}
        onOpenChange={(v) => !v && setConfirmFileDelete(null)}
        title="Delete file?"
        description="This removes the file and every rule inside it. This can't be undone."
      >
        <p className="mb-5 font-mono text-sm text-txt">
          Delete <span className="text-indigo-hi">{confirmFileDelete}</span> and all its rules?
        </p>
        <div className="flex justify-end gap-3">
          <Button variant="ghost" size="sm" onClick={() => setConfirmFileDelete(null)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={busy}
            onClick={() => confirmFileDelete && void deleteFile(confirmFileDelete)}
          >
            {busy ? 'Deleting…' : 'Delete file'}
          </Button>
        </div>
      </Modal>

      {toast && <Toast message={toast} onDone={() => setToast(null)} />}
    </div>
  )
}

// --- New file form ----------------------------------------------------------
function NewFileForm({
  busy,
  onSubmit,
  onCancel,
}: {
  busy: boolean
  onSubmit: (filename: string) => void
  onCancel: () => void
}) {
  const [filename, setFilename] = useState('')
  const [touched, setTouched] = useState(false)
  const invalid = filename.trim() === ''

  // Ensure a .dossier extension so files stay consistent with the ledger.
  const normalize = (raw: string) => {
    const t = raw.trim()
    return /\.[a-z0-9]+$/i.test(t) ? t : `${t}.dossier`
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setTouched(true)
    if (invalid) return
    onSubmit(normalize(filename))
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div>
        <label className={labelCls} htmlFor="new-file">
          File name
        </label>
        <input
          id="new-file"
          className={cn(fieldCls, 'font-mono')}
          value={filename}
          onChange={(e) => setFilename(e.target.value)}
          placeholder="custom-rules.dossier"
          autoFocus
        />
        {touched && invalid && fieldError('Give the file a name.')}
        <p className="mt-1.5 font-mono text-xs text-txt-dim">
          We'll add <span className="text-txt-muted">.dossier</span> if you skip the extension.
        </p>
      </div>
      <div className="flex justify-end gap-3 pt-2">
        <Button type="button" variant="ghost" size="sm" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" size="sm" disabled={busy}>
          {busy ? 'Creating…' : 'Create file'}
        </Button>
      </div>
    </form>
  )
}

// --- Test form --------------------------------------------------------------
function TestForm({
  filename,
  patternName,
  onClose,
  onError,
}: {
  filename: string
  patternName: string
  onClose: () => void
  onError: (msg: string) => void
}) {
  const [sample, setSample] = useState('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<PatternTestResponse | null>(null)

  const run = async (e: React.FormEvent) => {
    e.preventDefault()
    setRunning(true)
    setResult(null)
    try {
      const r = await patternsApi.test(filename, patternName, sample)
      setResult(r)
    } catch (err) {
      onError((err as Error)?.message ?? 'The test could not run. Try again.')
      onClose()
    } finally {
      setRunning(false)
    }
  }

  return (
    <form onSubmit={run} className="space-y-4">
      <div>
        <label className={labelCls} htmlFor="test-sample">
          Sample text
        </label>
        <textarea
          id="test-sample"
          className={cn(fieldCls, 'min-h-[7rem] resize-y font-mono')}
          value={sample}
          onChange={(e) => setSample(e.target.value)}
          placeholder="Paste text to run the rule against…"
          autoFocus
        />
      </div>

      <div className="flex justify-end gap-3">
        <Button type="button" variant="ghost" size="sm" onClick={onClose}>
          Close
        </Button>
        <Button type="submit" variant="primary" size="sm" disabled={running}>
          {running ? 'Running…' : 'Run test'}
        </Button>
      </div>

      {result && (
        <div className="card mt-2 space-y-3 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <span className={cn('badge', result.matched ? 'badge--cyan' : 'badge--muted')}>
              {result.matched ? 'Matched' : 'No match'}
            </span>
            <span className="font-mono text-xs text-txt-muted">
              {result.count} {result.count === 1 ? 'match' : 'matches'}
            </span>
          </div>
          {result.matches.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {result.matches.map((m, i) => (
                <span key={i} className="chip max-w-full truncate">
                  {m}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </form>
  )
}
