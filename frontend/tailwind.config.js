/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          500: '#8b5cf6', // Violeta brillante
          600: '#7c3aed',
        },
        secondary: {
          500: '#ec4899', // Rosa
        }
      }
    },
  },
  plugins: [],
}
