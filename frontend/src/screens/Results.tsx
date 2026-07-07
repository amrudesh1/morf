import { useMemo, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import * as Collapsible from '@radix-ui/react-collapsible'
import { ChevronDown, Copy, Search } from 'lucide-react'
import { useScan } from '@/store/scanStore'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'
import type { Confidence, NamedComponent, Activity, Secret } from '@/types'

const sevClass: Record<Confidence, string> = {
  high: 'sev--high',
  medium: 'sev--medium',
  low: 'sev--low',
}
const stampClass: Record<Confidence, string> = {
  high: 'stamp',
  medium: 'stamp stamp--signal',
  low: 'stamp stamp--muted',
}

const SEVERITIES: Confidence[] = ['high', 'medium', 'low']
type SevFilter = 'all' | Confidence

// Backend file paths are absolute inside the per-job workspace; trim everything
// up to the decompiled `output/` root so the user sees a readable relative path.
function cleanPath(p: string): string {
  const m = p.indexOf('output/')
  return m >= 0 ? p.slice(m) : p
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

  // Target identity: bundle id for iOS, package name (falling back to a
  // filename-style label) for Android. Read from `resultPlatform`, never the tab.
  const targetIdentity =
    resultPlatform === 'ios'
      ? iosMetadata?.bundleIdentifier || iosMetadata?.executableName || 'Unknown target'
      : metadata?.packageName || 'Unknown target'

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return secrets.filter((s) => {
      if (sevFilter !== 'all' && s.secretConfidence !== sevFilter) return false
      if (!q) return true
      const hay = `${s.secretType} ${s.type} ${s.secretString}`.toLowerCase()
      return hay.includes(q)
    })
  }, [secrets, query, sevFilter])

  const ease = [0.2, 0.8, 0.2, 1] as const
  // ONE tasteful moment: a staggered reveal of the evidence cards.
  const cardMotion = (i: number) =>
    reduce
      ? {}
      : {
          initial: { opacity: 0, y: 12 },
          animate: { opacity: 1, y: 0 },
          transition: { duration: 0.4, delay: Math.min(i * 0.05, 0.5), ease },
        }

  return (
    <div className="mx-auto flex min-h-screen max-w-4xl flex-col gap-8 px-6 py-12">
      {/* Scannable summary masthead — the headline verdict + severity + target. */}
      <section className="dossier flex flex-wrap items-end justify-between gap-6 p-6">
        <div className="space-y-3">
          <span className="eyebrow">Reconnaissance complete</span>
          <div className="flex items-baseline gap-3">
            <span className="font-display text-7xl text-oxblood">{secrets.length}</span>
            <span className="font-display text-3xl text-bone">Exposed</span>
          </div>
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
            {SEVERITIES.map((sev) => (
              <span key={sev} className="flex items-center gap-2 font-mono text-xs text-bone-dim">
                <span className={cn('sev', sevClass[sev])} />
                <span className="text-bone">{getSecretCountBySeverity(sev)}</span>
                <span className="uppercase tracking-widest">{sev}</span>
              </span>
            ))}
          </div>
        </div>
        <div className="space-y-2 text-right">
          <span
            className={cn(
              resultPlatform === 'ios' ? 'stamp stamp--signal' : 'stamp stamp--muted',
            )}
          >
            {resultPlatform === 'ios' ? 'iOS' : 'Android'}
          </span>
          <p className="max-w-xs break-all font-mono text-xs text-bone-dim">{targetIdentity}</p>
          <Button variant="ghost" size="sm" onClick={resetScan} className="justify-end">
            New case →
          </Button>
        </div>
      </section>

      {/* iOS target panel */}
      {resultPlatform === 'ios' && iosMetadata && (
        <section className="dossier space-y-4 p-6">
          <span className="eyebrow">Target · iOS</span>
          <div className="grid gap-2 md:grid-cols-2">
            <Ev k="Bundle ID" v={iosMetadata.bundleIdentifier} />
            <Ev k="Version" v={iosMetadata.bundleVersion} />
            <Ev k="Deployment target" v={iosMetadata.deploymentTarget} />
            <Ev k="Executable" v={iosMetadata.executableName} />
            <Ev k="Architectures" v={iosMetadata.architectures.join(', ')} />
            <div className="evidence">
              <span className="k">Encryption</span>
              <span className="lead" />
              <span className={iosMetadata.isEncrypted ? 'stamp' : 'stamp stamp--muted'}>
                {iosMetadata.isEncrypted ? 'Encrypted' : 'Exposed'}
              </span>
            </div>
          </div>

          {iosMetadata.urlSchemes.length > 0 && (
            <div className="space-y-1">
              <span className="eyebrow">URL schemes</span>
              <p className="font-mono text-xs text-signal">
                {iosMetadata.urlSchemes.join('  ·  ')}
              </p>
            </div>
          )}

          {iosMetadata.frameworks.length > 0 && (
            <div className="space-y-1">
              <span className="eyebrow">Frameworks · {iosMetadata.frameworks.length}</span>
              <p className="font-mono text-xs text-bone-dim">
                {iosMetadata.frameworks.join('  ·  ')}
              </p>
            </div>
          )}

          {Object.keys(iosMetadata.entitlements).length > 0 && (
            <div className="space-y-2">
              <span className="eyebrow">Entitlements</span>
              <div className="overflow-hidden rounded border border-ink-700">
                <table className="w-full border-collapse text-left font-mono text-xs">
                  <tbody>
                    {Object.entries(iosMetadata.entitlements).map(([k, v], i) => (
                      <tr
                        key={k}
                        className={cn('align-top', i % 2 === 1 && 'bg-ink-800/50')}
                      >
                        <td className="w-1/3 break-all px-3 py-2 text-bone-dim">{k}</td>
                        <td className="break-all px-3 py-2 text-bone">
                          {JSON.stringify(v)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      )}

      {/* Android target panel */}
      {resultPlatform === 'android' && metadata && (
        <section className="dossier space-y-4 p-6">
          <span className="eyebrow">Target · Android</span>
          <div className="grid gap-2 md:grid-cols-2">
            <Ev k="Package" v={metadata.packageName} />
            <Ev k="Version" v={metadata.version} />
            <Ev k="Min SDK" v={metadata.minSdk} />
            <Ev k="Target SDK" v={metadata.targetSdk} />
          </div>

          <div className="space-y-2">
            <ComponentSection
              title="Activities"
              items={metadata.activities.map((a: Activity) => a.name)}
            />
            <ComponentSection
              title="Services"
              items={metadata.services.map((c: NamedComponent) => c.name)}
            />
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
        </section>
      )}

      {/* Discovered secrets */}
      <section className="dossier p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <span className="eyebrow">Discovered secrets</span>
          <span className="font-mono text-xs text-bone-dim">
            {filtered.length} of {secrets.length} shown
          </span>
        </div>

        {secrets.length > 0 && (
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <label className="relative flex-1 min-w-[12rem]">
              <Search
                className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-bone-dim"
                aria-hidden
              />
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by type or value"
                aria-label="Filter secrets by type or value"
                className="w-full rounded border border-ink-700 bg-ink-900/60 py-2 pl-9 pr-3 font-mono text-xs text-bone placeholder:text-bone-dim focus:border-signal focus:outline-none"
              />
            </label>
            <div className="flex flex-wrap items-center gap-2">
              {(['all', ...SEVERITIES] as SevFilter[]).map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setSevFilter(f)}
                  aria-pressed={sevFilter === f}
                  className={cn(
                    'rounded border px-3 py-1.5 font-mono text-[0.65rem] uppercase tracking-widest transition-colors',
                    sevFilter === f
                      ? 'border-signal text-signal'
                      : 'border-ink-700 text-bone-dim hover:text-signal',
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="mt-4 space-y-3">
          {secrets.length === 0 && (
            <p className="font-mono text-sm text-bone-dim">No exposed secrets found.</p>
          )}
          {secrets.length > 0 && filtered.length === 0 && (
            <p className="font-mono text-sm text-bone-dim">
              No secrets match your filter.
            </p>
          )}
          {filtered.map((s, i) => (
            <SecretCard key={`${s.fileLocation}:${s.lineNo}:${i}`} secret={s} motion={cardMotion(i)} />
          ))}
        </div>
      </section>
    </div>
  )
}

function SecretCard({
  secret: s,
  motion: motionProps,
}: {
  secret: Secret
  motion: Record<string, unknown>
}) {
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard?.writeText(s.secretString)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1500)
  }

  return (
    <motion.div
      className="rounded border border-ink-700 bg-ink-800/60 p-4"
      {...motionProps}
    >
      <div className="flex items-center gap-3">
        <span className={cn('sev', sevClass[s.secretConfidence])} />
        <span className="font-display text-lg text-bone">{s.secretType || s.type}</span>
        <span className={cn('ml-auto', stampClass[s.secretConfidence])}>
          {s.secretConfidence}
        </span>
      </div>

      <div className="mt-3 flex items-center gap-3">
        <span className="font-mono text-xs text-bone-dim">value</span>
        {/* SIGNATURE — redaction bar reveals the leaked secret on hover/focus. */}
        <span
          className="redaction font-mono text-sm"
          tabIndex={0}
          role="button"
          title="Reveal secret"
          aria-label="Reveal secret value"
        >
          {s.secretString}
        </span>
        <Button
          variant="ghost"
          size="sm"
          onClick={copy}
          aria-label="Copy value"
          className="ml-auto text-[0.65rem]"
        >
          <Copy className="h-3 w-3" aria-hidden />
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>

      <p className="mt-2 font-mono text-xs text-bone-dim">
        {cleanPath(s.fileLocation)}:{s.lineNo}
      </p>
    </motion.div>
  )
}

function ComponentSection({ title, items }: { title: string; items: string[] }) {
  const [open, setOpen] = useState(false)
  if (items.length === 0) return null
  return (
    <Collapsible.Root open={open} onOpenChange={setOpen} className="rounded border border-ink-700">
      <Collapsible.Trigger className="flex w-full items-center justify-between px-4 py-3 text-left font-mono text-xs text-bone hover:text-signal">
        <span className="uppercase tracking-widest">
          {title} <span className="text-bone-dim">· {items.length}</span>
        </span>
        <ChevronDown
          className={cn('h-4 w-4 transition-transform', open && 'rotate-180')}
          aria-hidden
        />
      </Collapsible.Trigger>
      <Collapsible.Content className="border-t border-ink-700 px-4 py-3">
        <ul className="space-y-1 font-mono text-xs text-bone-dim">
          {items.map((name, i) => (
            <li key={`${name}:${i}`} className="break-all">
              {name}
            </li>
          ))}
        </ul>
      </Collapsible.Content>
    </Collapsible.Root>
  )
}

function Ev({ k, v }: { k: string; v: string }) {
  return (
    <div className="evidence">
      <span className="k">{k}</span>
      <span className="lead" />
      <span className="v">{v || '—'}</span>
    </div>
  )
}
