import { useMemo, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import * as Collapsible from '@radix-ui/react-collapsible'
import {
  ChevronDown,
  Copy,
  Check,
  Search,
  Lock,
  Unlock,
  ShieldCheck,
  Plus,
  RotateCcw,
} from 'lucide-react'
import { useScan } from '@/store/scanStore'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'
import { useCountUp } from '@/lib/useCountUp'
import type { Confidence, NamedComponent, Activity, Secret } from '@/types'

const sevDot: Record<Confidence, string> = {
  high: 'sev-dot--high',
  medium: 'sev-dot--med',
  low: 'sev-dot--low',
}
const sevBadge: Record<Confidence, string> = {
  high: 'badge badge--high',
  medium: 'badge badge--med',
  low: 'badge badge--low',
}
const SEVERITIES: Confidence[] = ['high', 'medium', 'low']
type SevFilter = 'all' | Confidence

// Backend paths are absolute inside the per-job workspace; trim to the readable root.
function cleanPath(p: string): string {
  const i = p.indexOf('output/')
  return i >= 0 ? p.slice(i) : p
}

export function Results() {
  const {
    secrets,
    resultPlatform,
    iosMetadata,
    metadata,
    getSecretCountBySeverity,
    resetScan,
  } = useScan()
  const reduce = useReducedMotion()
  const [query, setQuery] = useState('')
  const [sevFilter, setSevFilter] = useState<SevFilter>('all')
  const count = useCountUp(secrets.length)

  const targetIdentity =
    resultPlatform === 'ios'
      ? iosMetadata?.bundleIdentifier || iosMetadata?.executableName || 'Unknown target'
      : metadata?.packageName || 'Unknown target'

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return secrets.filter((s) => {
      if (sevFilter !== 'all' && s.secretConfidence !== sevFilter) return false
      if (!q) return true
      return `${s.secretType} ${s.type} ${s.secretString}`.toLowerCase().includes(q)
    })
  }, [secrets, query, sevFilter])

  const ease = [0.2, 0.8, 0.2, 1] as const
  // Scroll-reveal for the below-the-fold metadata panels.
  const scrollReveal = reduce
    ? {}
    : {
        initial: { opacity: 0, y: 16 },
        whileInView: { opacity: 1, y: 0 },
        viewport: { once: true, margin: '-10% 0px' },
        transition: { duration: 0.5, ease },
      }
  const rise = (i: number) =>
    reduce
      ? {}
      : {
          initial: { opacity: 0, y: 14 },
          animate: { opacity: 1, y: 0 },
          transition: { duration: 0.4, delay: Math.min(i * 0.05, 0.4), ease },
        }

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-10 md:px-6">
      {/* Summary masthead */}
      <motion.section className="card overflow-hidden p-6 md:p-8" {...rise(0)}>
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div>
            <span className="eyebrow text-txt-dim">Reconnaissance complete</span>
            <div className="mt-3 flex items-end gap-3">
              <span className="gradient-text font-display text-6xl font-bold leading-none md:text-7xl tabular-nums">
                {count}
              </span>
              <span className="pb-1 font-display text-2xl font-semibold text-txt-muted">
                {secrets.length === 1 ? 'secret exposed' : 'secrets exposed'}
              </span>
            </div>
            <div className="mt-5 flex flex-wrap items-center gap-2">
              {SEVERITIES.map((sev) => (
                <span key={sev} className={cn(sevBadge[sev])}>
                  <span className={cn('sev-dot', sevDot[sev])} />
                  {getSecretCountBySeverity(sev)} {sev}
                </span>
              ))}
            </div>
          </div>
          <div className="flex flex-col items-end gap-3">
            <span
              className={cn('badge', resultPlatform === 'ios' ? 'badge--cyan' : 'badge--indigo')}
            >
              {resultPlatform === 'ios' ? 'iOS' : 'Android'}
            </span>
            <span className="max-w-[16rem] break-all text-right font-mono text-xs text-txt-muted">
              {targetIdentity}
            </span>
            <Button variant="ghost" size="sm" onClick={resetScan}>
              <RotateCcw className="h-3.5 w-3.5" /> New scan
            </Button>
          </div>
        </div>
      </motion.section>

      {/* Findings */}
      <motion.section className="flex flex-col gap-4" {...rise(1)}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-display text-xl font-semibold text-txt">Discovered secrets</h2>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-txt-dim" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by type or value…"
                aria-label="Filter secrets"
                className="w-56 rounded-lg border border-line bg-surface py-2 pl-9 pr-3 font-mono text-xs text-txt placeholder:text-txt-dim focus:border-indigo focus:outline-none"
              />
            </div>
            <div className="flex items-center gap-1 rounded-lg border border-line bg-surface p-1">
              {(['all', ...SEVERITIES] as SevFilter[]).map((f) => (
                <button
                  key={f}
                  onClick={() => setSevFilter(f)}
                  aria-pressed={sevFilter === f}
                  className={cn(
                    'rounded-md px-2.5 py-1 font-mono text-[0.68rem] uppercase tracking-wider transition-colors',
                    sevFilter === f ? 'bg-surface-hi text-txt' : 'text-txt-dim hover:text-txt-muted',
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
        </div>

        {secrets.length === 0 ? (
          <div className="card flex flex-col items-center gap-2 px-6 py-14 text-center">
            <ShieldCheck className="h-8 w-8 text-sev-low" />
            <p className="font-display text-lg text-txt">No exposed secrets found</p>
            <p className="max-w-sm text-sm text-txt-muted">
              MORF ran every detection rule against this build and came up clean.
            </p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="card px-6 py-10 text-center text-sm text-txt-muted">
            No secrets match your filter.
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {filtered.map((s, i) => (
              <SecretCard key={`${s.fileLocation}:${s.lineNo}:${i}`} secret={s} index={i} reduce={!!reduce} />
            ))}
          </div>
        )}
      </motion.section>

      {/* iOS target panel */}
      {resultPlatform === 'ios' && iosMetadata && (
        <motion.section className="card p-6 md:p-8" {...scrollReveal}>
          <SectionTitle>Target · iOS</SectionTitle>
          <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Stat k="Bundle ID" v={iosMetadata.bundleIdentifier || '—'} mono />
            <Stat k="Version" v={iosMetadata.bundleVersion || '—'} mono />
            <Stat k="Deployment target" v={iosMetadata.deploymentTarget || '—'} mono />
            <Stat k="Executable" v={iosMetadata.executableName || '—'} mono />
            <Stat k="Architectures" v={iosMetadata.architectures.join(', ') || '—'} mono />
            <div className="stat">
              <span className="k">Encryption</span>
              <span className="mt-1">
                <span className={cn('badge', iosMetadata.isEncrypted ? 'badge--cyan' : 'badge--high')}>
                  {iosMetadata.isEncrypted ? <Lock className="h-3 w-3" /> : <Unlock className="h-3 w-3" />}
                  {iosMetadata.isEncrypted ? 'Encrypted' : 'Exposed'}
                </span>
              </span>
            </div>
          </div>

          {iosMetadata.urlSchemes.length > 0 && (
            <ChipList title="URL schemes" items={iosMetadata.urlSchemes} accent />
          )}
          {iosMetadata.frameworks.length > 0 && (
            <ChipList title="Frameworks" items={iosMetadata.frameworks} />
          )}

          {Object.keys(iosMetadata.entitlements).length > 0 && (
            <div className="mt-6">
              <span className="eyebrow">
                Entitlements · {Object.keys(iosMetadata.entitlements).length}
              </span>
              <div className="mt-2 overflow-hidden rounded-lg border border-line">
                <table className="data-table">
                  <tbody>
                    {Object.entries(iosMetadata.entitlements).map(([k, v]) => (
                      <tr key={k}>
                        <td>{k}</td>
                        <td>{typeof v === 'string' ? v : JSON.stringify(v)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </motion.section>
      )}

      {/* Android target panel */}
      {resultPlatform === 'android' && metadata && (
        <motion.section className="card p-6 md:p-8" {...scrollReveal}>
          <SectionTitle>Target · Android</SectionTitle>
          <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat k="Package" v={metadata.packageName || '—'} mono />
            <Stat k="Version" v={metadata.version || '—'} mono />
            <Stat k="Min SDK" v={metadata.minSdk || '—'} mono />
            <Stat k="Target SDK" v={metadata.targetSdk || '—'} mono />
          </div>
          <div className="mt-6 flex flex-col gap-2">
            <ComponentSection title="Activities" items={metadata.activities.map((a: Activity) => a.name)} />
            <ComponentSection title="Services" items={metadata.services.map((c: NamedComponent) => c.name)} />
            <ComponentSection
              title="Content providers"
              items={metadata.contentProviders.map((c: NamedComponent) => c.name)}
            />
            <ComponentSection
              title="Broadcast receivers"
              items={metadata.broadcastReceivers.map((c: NamedComponent) => c.name)}
            />
            <ComponentSection title="Permissions" items={metadata.permissions} />
          </div>
        </motion.section>
      )}
    </div>
  )
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <h2 className="font-display text-lg font-semibold text-txt">{children}</h2>
}

function Stat({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="stat">
      <span className="k">{k}</span>
      <span className={cn('v break-all', mono && 'font-mono text-sm')}>{v}</span>
    </div>
  )
}

// A wrapped list of pills, with expand-all when there are many.
function ChipList({ title, items, accent }: { title: string; items: string[]; accent?: boolean }) {
  const [open, setOpen] = useState(false)
  const LIMIT = 24
  const shown = open ? items : items.slice(0, LIMIT)
  const hidden = items.length - shown.length
  return (
    <div className="mt-6">
      <span className="eyebrow">
        {title} · {items.length}
      </span>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {shown.map((it) => (
          <span key={it} className={cn('chip', accent && 'border-cyan/30 text-cyan')}>
            {it}
          </span>
        ))}
        {hidden > 0 && (
          <button
            onClick={() => setOpen(true)}
            className="chip border-indigo/40 text-indigo-hi hover:text-indigo-hi"
          >
            <Plus className="h-3 w-3" /> {hidden} more
          </button>
        )}
      </div>
    </div>
  )
}

function ComponentSection({ title, items }: { title: string; items: string[] }) {
  const [open, setOpen] = useState(false)
  const reduce = useReducedMotion()
  if (items.length === 0) return null
  return (
    <Collapsible.Root open={open} onOpenChange={setOpen}>
      <Collapsible.Trigger className="flex w-full items-center justify-between rounded-lg border border-line bg-surface px-4 py-3 text-left transition-colors hover:border-line-hi">
        <span className="flex items-center gap-2 text-sm font-medium text-txt">
          {title}
          <span className="badge badge--muted">{items.length}</span>
        </span>
        <ChevronDown className={cn('h-4 w-4 text-txt-dim transition-transform', open && 'rotate-180')} />
      </Collapsible.Trigger>
      <Collapsible.Content className="overflow-hidden">
        <motion.div
          className="flex flex-wrap gap-1.5 px-1 py-3"
          initial={reduce ? false : 'hidden'}
          animate="show"
          variants={{ show: { transition: { staggerChildren: 0.015 } } }}
        >
          {items.map((it, i) => (
            <motion.span
              key={`${it}-${i}`}
              className="chip"
              variants={reduce ? undefined : { hidden: { opacity: 0, y: 6 }, show: { opacity: 1, y: 0 } }}
            >
              {it}
            </motion.span>
          ))}
        </motion.div>
      </Collapsible.Content>
    </Collapsible.Root>
  )
}

function SecretCard({ secret, index, reduce }: { secret: Secret; index: number; reduce: boolean }) {
  const [copied, setCopied] = useState(false)
  const [revealed, setRevealed] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard?.writeText(secret.secretString)
      setCopied(true)
      setTimeout(() => setCopied(false), 1600)
    } catch {
      /* clipboard unavailable */
    }
  }
  const motionProps = reduce
    ? {}
    : {
        initial: { opacity: 0, y: 10 },
        animate: { opacity: 1, y: 0 },
        transition: { duration: 0.35, delay: Math.min(index * 0.04, 0.4) },
      }
  return (
    <motion.div className="card card-hover p-5" {...motionProps}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span className={cn('sev-dot', sevDot[secret.secretConfidence])} />
          <span className="font-display text-base font-semibold text-txt">
            {secret.secretType || secret.type}
          </span>
        </div>
        <span className={cn(sevBadge[secret.secretConfidence])}>{secret.secretConfidence}</span>
      </div>

      <div className="mt-4 flex items-center gap-2">
        <span
          role="button"
          tabIndex={0}
          onClick={() => setRevealed((r) => !r)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              setRevealed((r) => !r)
            }
          }}
          className={cn('reveal min-w-0 flex-1 text-sm', revealed && 'revealed')}
          aria-label="Secret value — activate to reveal"
        >
          {secret.secretString}
        </span>
        <button
          onClick={copy}
          aria-label="Copy secret value"
          className="flex shrink-0 items-center gap-1.5 rounded-lg border border-line bg-surface px-2.5 py-2 font-mono text-xs text-txt-muted transition-colors hover:border-line-hi hover:text-txt"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-sev-low" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>

      <p className="mt-3 truncate font-mono text-xs text-txt-dim" title={secret.fileLocation}>
        {cleanPath(secret.fileLocation)}
        {secret.lineNo ? `:${secret.lineNo}` : ''}
      </p>
    </motion.div>
  )
}
