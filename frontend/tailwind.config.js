/** @type {import('tailwindcss').Config} */
// MORF (Mobile Reconnaissance Framework) — "Forensic Dossier" visual system.
// Thesis: MORF exposes secrets that were meant to stay hidden, so the UI treats
// findings like declassified evidence. Boldness is spent on ONE signature (the
// redaction bar that reveals a leaked secret); everything else stays quiet.
// NOTE: this is a visual treatment only — the product is always named
// "MORF - Mobile Reconnaissance Framework".
module.exports = {
  content: ["./src/**/*.{html,ts}"],
  theme: {
    extend: {
      colors: {
        // Warm near-black "field" and raised document surfaces.
        ink: {
          DEFAULT: "#14110F", // page
          800: "#1D1916", // raised card / dossier panel
          700: "#2A2420", // hairline borders on dark
          900: "#0A0806", // redaction fill (pure ink)
        },
        // Bone paper — primary text on dark, and the surface of "document" panels.
        bone: {
          DEFAULT: "#EDE6D6",
          dim: "#B9AC93", // manila — secondary text, captions
        },
        // Amber is the single signal accent: highlights, links, medium severity.
        signal: {
          DEFAULT: "#E8A33D",
          hi: "#F5B657",
        },
        // Oxblood marks alerts / high-severity exposure.
        oxblood: {
          DEFAULT: "#A83232",
          deep: "#7A2222",
        },
      },
      fontFamily: {
        // display: heavy condensed grotesque for statements (MORF, EXPOSED, counts)
        display: ['Anton', 'Arial Narrow', 'sans-serif'],
        // ui/body grotesque
        sans: ['Archivo', 'system-ui', 'sans-serif'],
        // typewritten evidence / data / paths
        mono: ['"Space Mono"', 'ui-monospace', 'monospace'],
      },
      letterSpacing: {
        stamp: '0.18em',
      },
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
}
