import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/auth': 'http://localhost:8000',
      '/me': 'http://localhost:8000',
      '/chat': 'http://localhost:8000',
      '/conversations': 'http://localhost:8000',
      '/scan': 'http://localhost:8000',
      '/documents': 'http://localhost:8000',
      '/roles': 'http://localhost:8000',
      '/permissions': 'http://localhost:8000',
      '/access': 'http://localhost:8000',
      '/access-grants': 'http://localhost:8000',
      '/access-audit': 'http://localhost:8000',
      '/users': 'http://localhost:8000',
      '/demo': 'http://localhost:8000',
      '/chunks': 'http://localhost:8000',
      '/logs': 'http://localhost:8000',
      '/admin': 'http://localhost:8000',
      '/audit': 'http://localhost:8000',
      '/lab': 'http://localhost:8000',
    }
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.js'],
  },
})
