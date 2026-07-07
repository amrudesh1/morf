import { forwardRef } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/cn'

// Electric-slate button system. primary = indigo→cyan gradient action;
// outline = indigo border; ghost = quiet link; danger = severity red.
// All keyboard-focusable via the global :focus-visible ring.
const button = cva(
  'inline-flex items-center justify-center gap-2 rounded-lg font-sans font-semibold transition-all disabled:opacity-50 disabled:pointer-events-none select-none',
  {
    variants: {
      variant: {
        primary:
          'bg-gradient-to-r from-indigo to-cyan text-base shadow-[0_8px_24px_-10px_rgba(99,102,241,0.7)] hover:brightness-110 hover:shadow-[0_10px_30px_-8px_rgba(34,211,238,0.6)]',
        outline: 'border border-indigo/50 text-indigo-hi hover:bg-indigo/10 hover:border-indigo',
        ghost: 'text-txt-muted hover:text-txt hover:bg-surface-hi',
        danger: 'border border-sev-high/50 text-sev-high hover:bg-sev-high/10 hover:border-sev-high',
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
