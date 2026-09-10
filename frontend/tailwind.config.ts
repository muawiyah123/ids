/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // IDS Sentinel design system — dark SOC palette
        sentinel: {
          bg: '#0a0e1a',         // Deep navy black
          surface: '#0f1629',    // Card background
          panel: '#141e35',      // Panel
          border: '#1e2d4a',     // Border
          muted: '#243354',      // Muted elements
          text: '#e2e8f0',       // Primary text
          subtle: '#94a3b8',     // Secondary text
          accent: '#3b82f6',     // Blue accent
          'accent-dim': '#1d4ed8', // Darker accent
        },
        threat: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
          info: '#10b981',
          benign: '#10b981',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.2s ease-out',
      },
      keyframes: {
        slideIn: {
          '0%': { transform: 'translateY(-8px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
