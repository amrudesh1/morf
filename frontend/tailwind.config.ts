import type { Config } from 'tailwindcss'

// MORF (Mobile Reconnaissance Framework) — "Forensic Dossier" visual system.
// Ported verbatim from the Angular app so the identity is unchanged.
// Product name is always "MORF - Mobile Reconnaissance Framework".
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          DEFAULT: '#14110F',
          800: '#1D1916',
          700: '#2A2420',
          900: '#0A0806',
        },
        bone: {
          DEFAULT: '#EDE6D6',
          dim: '#B9AC93',
        },
        signal: {
          DEFAULT: '#E8A33D',
          hi: '#F5B657',
        },
        oxblood: {
          DEFAULT: '#A83232',
          deep: '#7A2222',
        },
      },
      fontFamily: {
        display: ['Anton', 'Arial Narrow', 'sans-serif'],
        sans: ['Archivo', 'system-ui', 'sans-serif'],
        mono: ['"Space Mono"', 'ui-monospace', 'monospace'],
      },
      letterSpacing: { stamp: '0.18em' },
      keyframes: {
        'stamp-in': {
          '0%': { opacity: '0', transform: 'rotate(-6deg) scale(1.6)' },
          '60%': { opacity: '1' },
          '100%': { opacity: '0.92', transform: 'rotate(-6deg) scale(1)' },
        },
        'scan-sweep': {
          '0%': { transform: 'translateY(-120%)' },
          '100%': { transform: 'translateY(120%)' },
        },
        'file-in': {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'stamp-in': 'stamp-in 0.45s cubic-bezier(.2,.8,.2,1) both',
        'scan-sweep': 'scan-sweep 2.4s ease-in-out infinite',
        'file-in': 'file-in 0.4s ease-out both',
      },
    },
  },
  plugins: [],
} satisfies Config
