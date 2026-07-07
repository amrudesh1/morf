import { forwardRef } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/cn'

// Dossier button system. Primary = amber signal action; ghost = quiet mono link;
// danger = oxblood. All keyboard-focusable via the global :focus-visible ring.
const button = cva(
  'inline-flex items-center justify-center gap-2 rounded font-sans font-semibold transition-colors disabled:opacity-50 disabled:pointer-events-none select-none',
  {
    variants: {
      variant: {
        primary: 'bg-signal text-ink hover:bg-signal-hi',
        outline: 'border border-signal/70 text-signal hover:bg-signal/10',
        ghost: 'font-mono uppercase tracking-widest text-bone-dim hover:text-signal',
        danger: 'border border-oxblood text-oxblood hover:bg-oxblood/10',
      },
      size: {
        sm: 'px-3 py-1.5 text-xs',
        md: 'px-4 py-2 text-sm',
        lg: 'px-6 py-3 text-base',
      },
    },
    defaultVariants: { variant: 'primary', size: 'md' },
  },
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button ref={ref} className={cn(button({ variant, size }), className)} {...props} />
  ),
)
Button.displayName = 'Button'
