import type { Config } from 'tailwindcss'

// MORF (Mobile Reconnaissance Framework) — "Electric Slate" visual system.
// A modern security-dashboard look: deep-slate layered surfaces, an indigo→cyan
// accent, and severity-coded signals. Mono is reserved for code + secret values.
// Product name is always "MORF - Mobile Reconnaissance Framework".
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Layered dark surfaces (page → card → elevated).
        base: { DEFAULT: '#0A0E17', hi: '#0E131F' },
        surface: { DEFAULT: '#111826', hi: '#18202F' },
        line: { DEFAULT: '#212B3E', hi: '#2C3850' },
        // Text ramp.
        txt: { DEFAULT: '#E8EDF6', muted: '#94A2BC', dim: '#5E6B85' },
        // Accent: electric indigo → cyan.
        indigo: { DEFAULT: '#6366F1', hi: '#818CF8', deep: '#4F46E5' },
        cyan: { DEFAULT: '#22D3EE', hi: '#67E8F9' },
        // Severity signals.
        sev: { high: '#FB5C74', med: '#F5A623', low: '#4FB3F6' },
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'system-ui', 'sans-serif'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      borderRadius: { xl: '0.875rem', '2xl': '1.125rem' },
      boxShadow: {
        card: '0 1px 0 rgba(255,255,255,0.03) inset, 0 20px 40px -28px rgba(0,0,0,0.9)',
        glow: '0 0 0 1px rgba(99,102,241,0.4), 0 8px 30px -8px rgba(99,102,241,0.45)',
        'glow-cyan': '0 0 0 1px rgba(34,211,238,0.35), 0 8px 30px -8px rgba(34,211,238,0.4)',
      },
      keyframes: {
        'scan-sweep': {
          '0%': { transform: 'translateY(-120%)' },
          '100%': { transform: 'translateY(120%)' },
        },
        'file-in': {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'glow-pulse': {
          '0%, 100%': { opacity: '0.55' },
          '50%': { opacity: '1' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        breathe: {
          '0%, 100%': { filter: 'drop-shadow(0 0 14px rgba(129,140,248,0.45))' },
          '50%': { filter: 'drop-shadow(0 0 34px rgba(34,211,238,0.7))' },
        },
        particle: {
          '0%': { opacity: '0', transform: 'translateY(0) scale(0.5)' },
          '50%': { opacity: '0.7' },
          '100%': { opacity: '0', transform: 'translateY(-14px) scale(1)' },
        },
        'ping-ring': {
          '0%': { transform: 'scale(0.7)', opacity: '0.5' },
          '100%': { transform: 'scale(2.1)', opacity: '0' },
        },
        'dot-pulse': {
          '0%, 100%': { opacity: '0.25', transform: 'scale(0.8)' },
          '50%': { opacity: '1', transform: 'scale(1.15)' },
        },
      },
      animation: {
        'scan-sweep': 'scan-sweep 2.4s ease-in-out infinite',
        'file-in': 'file-in 0.4s ease-out both',
        'glow-pulse': 'glow-pulse 2.4s ease-in-out infinite',
        shimmer: 'shimmer 2.2s linear infinite',
        breathe: 'breathe 2.6s ease-in-out infinite',
        particle: 'particle 3s ease-in-out infinite',
        'ping-ring': 'ping-ring 3s ease-out infinite',
        'dot-pulse': 'dot-pulse 1s ease-in-out infinite',
      },
    },
  },
  plugins: [],
} satisfies Config
