import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from 'react-query'
import { Toaster } from 'react-hot-toast'
import { AppProvider } from './context/AppContext'

import App from './App'
import './index.css'
import ErrorBoundary from './components/ErrorBoundary'

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AppProvider>
            <App />
            <Toaster
              position="top-right"
              toastOptions={{
                duration: 4000,
                style: {
                  background: '#1a1a2e',
                  color: '#00d4ff',
                  border: '1px solid #00d4ff',
                  borderRadius: '8px',
                  boxShadow: '0 4px 6px -1px rgba(0, 212, 255, 0.3)',
                },
                success: {
                  iconTheme: {
                    primary: '#00ff88',
                    secondary: '#1a1a2e',
                  },
                },
                error: {
                  iconTheme: {
                    primary: '#ff6b9d',
                    secondary: '#1a1a2e',
                  },
                },
              }}
            />
          </AppProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>,
) 