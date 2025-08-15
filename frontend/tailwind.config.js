/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Cyberpunk color palette - toned down for better readability
        'cyber-black': '#0a0a0a',
        'cyber-dark': '#1a1a1a',
        'cyber-gray': '#3a3a3a',
        'cyber-light': '#5a5a5a',
        'cyber-white': '#e8e8e8',
        'cyber-muted': '#999999',
        'neon-cyan': '#4dd0e1',
        'neon-pink': '#e91e63',
        'neon-green': '#66bb6a',
        'neon-orange': '#ff7043',
        'neon-red': '#ef5350',
        'neon-purple': '#ab47bc',
        'neon-blue': '#42a5f5',
        'electric-blue': '#29b6f6',
        'matrix-green': '#81c784',
        // Semantic colors
        'primary': '#4dd0e1',
        'secondary': '#e91e63',
        'accent': '#66bb6a',
        'warning': '#ff7043',
        'danger': '#ef5350',
        'success': '#81c784',
        'info': '#29b6f6',
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'monospace'],
        'cyber': ['Orbitron', 'sans-serif'],
      },
      animation: {
        'glow': 'glow 2s ease-in-out infinite alternate',
        'pulse-neon': 'pulse-neon 1.5s ease-in-out infinite',
        'scan-line': 'scan-line 2s linear infinite',
        'matrix-rain': 'matrix-rain 20s linear infinite',
        'flicker': 'flicker 0.15s ease-in-out infinite alternate',
        'cyber-fade-in': 'cyber-fade-in 0.5s ease-out',
        'slide-up': 'slide-up 0.3s ease-out',
        'slide-down': 'slide-down 0.3s ease-out',
      },
      keyframes: {
        glow: {
          '0%': { 
            boxShadow: '0 0 3px currentColor, 0 0 6px currentColor'
          },
          '100%': { 
            boxShadow: '0 0 6px currentColor, 0 0 12px currentColor'
          }
        },
        'pulse-neon': {
          '0%, 100%': { 
            textShadow: '0 0 5px currentColor, 0 0 10px currentColor, 0 0 15px currentColor',
            opacity: '1'
          },
          '50%': { 
            textShadow: '0 0 2px currentColor, 0 0 5px currentColor, 0 0 8px currentColor',
            opacity: '0.8'
          }
        },
        'scan-line': {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' }
        },
        'matrix-rain': {
          '0%': { transform: 'translateY(-100vh)' },
          '100%': { transform: 'translateY(100vh)' }
        },
        flicker: {
          '0%': { opacity: '1' },
          '100%': { opacity: '0.95' }
        },
        'cyber-fade-in': {
          '0%': { 
            opacity: '0',
            transform: 'translateY(20px) scale(0.95)',
          },
          '100%': { 
            opacity: '1',
            transform: 'translateY(0) scale(1)',
          }
        },
        'slide-up': {
          '0%': { 
            opacity: '0',
            transform: 'translateY(20px)',
          },
          '100%': { 
            opacity: '1',
            transform: 'translateY(0)',
          }
        },
        'slide-down': {
          '0%': { 
            opacity: '0',
            transform: 'translateY(-20px)',
          },
          '100%': { 
            opacity: '1',
            transform: 'translateY(0)',
          }
        }
      },
      backgroundImage: {
        'cyber-gradient': 'linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 50%, #0a0a0a 100%)',
        'neon-gradient': 'linear-gradient(90deg, #00ffff, #ff00ff, #00ff00)',
        'matrix-bg': 'radial-gradient(ellipse at center, #001a00 0%, #000000 70%)',
      },
      boxShadow: {
        'neon': '0 0 5px currentColor, 0 0 10px currentColor, 0 0 15px currentColor',
        'neon-lg': '0 0 10px currentColor, 0 0 20px currentColor, 0 0 30px currentColor',
        'cyber': '0 0 20px rgba(0, 255, 255, 0.3), 0 0 40px rgba(0, 255, 255, 0.1)',
        'inner-neon': 'inset 0 0 10px currentColor',
      },
      backdropBlur: {
        'xs': '2px',
      },
    },
  },
  plugins: [
    function({ addUtilities }) {
      const newUtilities = {
        '.text-glow': {
          textShadow: '0 0 2px currentColor, 0 0 4px currentColor',
        },
        '.text-glow-lg': {
          textShadow: '0 0 4px currentColor, 0 0 8px currentColor',
        },
        '.border-glow': {
          boxShadow: '0 0 3px currentColor, 0 0 6px currentColor',
        },
        '.border-glow-lg': {
          boxShadow: '0 0 6px currentColor, 0 0 12px currentColor',
        },
        '.cyber-grid': {
          backgroundImage: `
            linear-gradient(rgba(77, 208, 225, 0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(77, 208, 225, 0.05) 1px, transparent 1px)
          `,
          backgroundSize: '20px 20px',
        },
        '.scan-lines': {
          position: 'relative',
          '&::before': {
            content: '""',
            position: 'absolute',
            top: '0',
            left: '0',
            right: '0',
            bottom: '0',
            background: 'linear-gradient(transparent 49%, rgba(77, 208, 225, 0.03) 50%, transparent 51%)',
            backgroundSize: '100% 4px',
            pointerEvents: 'none',
            animation: 'scan-line 2s linear infinite',
          }
        }
      }
      addUtilities(newUtilities)
    }
  ],
} 