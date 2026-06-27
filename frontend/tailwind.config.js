/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    './index.html',
    './src/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        // Severity palette — matches the Go models.Severity constants.
        severity: {
          critical: { bg: '#7f1d1d', text: '#fca5a5', border: '#991b1b' },
          high:     { bg: '#7c2d12', text: '#fdba74', border: '#9a3412' },
          medium:   { bg: '#713f12', text: '#fde047', border: '#854d0e' },
          low:      { bg: '#1e3a5f', text: '#93c5fd', border: '#1d4ed8' },
          unknown:  { bg: '#1f2937', text: '#9ca3af', border: '#374151' },
        },
      },
      animation: {
        'slide-in': 'slideIn 0.25s ease-out',
        'fade-in':  'fadeIn 0.15s ease-out',
        'progress': 'progress 1.5s ease-in-out infinite',
      },
      keyframes: {
        slideIn: {
          '0%':   { transform: 'translateX(100%)' },
          '100%': { transform: 'translateX(0)' },
        },
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
        progress: {
          '0%':   { backgroundPosition: '0% 50%' },
          '100%': { backgroundPosition: '200% 50%' },
        },
      },
    },
  },
  plugins: [],
};
