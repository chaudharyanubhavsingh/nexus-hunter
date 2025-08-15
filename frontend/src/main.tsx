import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from 'react-query'
import { Toaster } from 'react-hot-toast'
import { AppProvider } from './context/AppContext'

import App from './App'
import './index.css'

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppProvider>
          <App />
          <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#1a1a1a',
              color: '#4dd0e1',
              border: '1px solid #4dd0e1',
              borderRadius: '8px',
                              boxShadow: '0 0 10px rgba(77, 208, 225, 0.2)',
              fontFamily: 'JetBrains Mono, monospace',
            },
            success: {
              iconTheme: {
                primary: '#00ff41',
                secondary: '#1a1a1a',
              },
            },
            error: {
              iconTheme: {
                primary: '#ff0040',
                secondary: '#1a1a1a',
              },
            },
          }}
        />
        </AppProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
) 