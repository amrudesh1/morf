import { cn } from '@/lib/cn'

// Dynamic, responsive ambient backdrop: gradient blobs that drift and scale with
// the viewport (vmax units → never looks stretched), over a faint moving grid.
// `intense` for the splash; the softer default sits behind app screens.
// Motion auto-stops under prefers-reduced-motion (global CSS) while staying elegant.
export function AuroraBackground({ intense = false }: { intense?: boolean }) {
  const o = intense ? '' : 'opacity-70'
  return (
    <div aria-hidden className={cn('pointer-events-none absolute inset-0 overflow-hidden', o)}>
      <div
        className={cn(
          'absolute -left-[8%] -top-[6%] rounded-full bg-indigo/30 blur-[120px] animate-drift',
          intense ? 'h-[46vmax] w-[46vmax]' : 'h-[38vmax] w-[38vmax]',
        )}
      />
      <div
        className={cn(
          'absolute -right-[6%] top-[24%] rounded-full bg-cyan/20 blur-[130px] animate-drift2',
          intense ? 'h-[42vmax] w-[42vmax]' : 'h-[34vmax] w-[34vmax]',
        )}
      />
      <div
        className={cn(
          'absolute bottom-[-10%] left-[28%] rounded-full bg-indigo-deep/28 blur-[120px] animate-drift',
          intense ? 'h-[40vmax] w-[40vmax]' : 'h-[32vmax] w-[32vmax]',
        )}
        style={{ animationDelay: '-7s' }}
      />
      {intense && (
        <div
          className="absolute right-[16%] top-[8%] h-[24vmax] w-[24vmax] rounded-full bg-cyan/15 blur-[100px] animate-drift2"
          style={{ animationDelay: '-11s' }}
        />
      )}
    </div>
  )
}
