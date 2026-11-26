import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // In dev, forward API calls to the FastAPI backend (same-origin in the desktop app)
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
})
