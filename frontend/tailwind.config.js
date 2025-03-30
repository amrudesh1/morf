/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{html,ts}",
  ],
  theme: {
    extend: {
      colors: {
        'custom-blue': '#030E31',
        'custom-text': '#93C1F7'
      }
    },
  },
  plugins: [],
}
