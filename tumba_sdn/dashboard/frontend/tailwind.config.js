/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        campus: {
          ink: '#e5edf8',
          muted: '#9fb2ca',
          line: '#263a56',
          panel: '#101b2d',
          bg: '#07111f'
        }
      },
      boxShadow: {
        panel: '0 18px 45px rgba(0, 0, 0, 0.26)'
      }
    }
  },
  plugins: []
};
