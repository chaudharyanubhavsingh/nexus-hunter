/**
 * Login Page Component
 * Authentication interface with intentional vulnerabilities
 */

import React, { useState, useEffect } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline'
import toast from 'react-hot-toast'

import { useAuth } from '@services/AuthContext'

const LoginPage: React.FC = () => {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [rememberMe, setRememberMe] = useState(false)

  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const from = location.state?.from?.pathname || '/dashboard'

  // VULNERABLE: Log authentication attempts
  useEffect(() => {
    console.log('Login page accessed from:', from)
    console.log('User agent:', navigator.userAgent)
    console.log('Referrer:', document.referrer)
    
    // VULNERABLE: Expose debug information
    if (process.env.NODE_ENV === 'development') {
      (window as any).loginDebug = {
        from,
        timestamp: new Date().toISOString(),
        sessionId: Date.now().toString()
      }
    }
  }, [from])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    // VULNERABLE: Client-side validation only
    if (!username.trim() || !password.trim()) {
      toast.error('Please enter both username and password')
      return
    }

    setLoading(true)

    try {
      // VULNERABLE: Log credentials for "debugging"
      console.log('Login attempt:', { username, passwordLength: password.length })
      
      const success = await login(username, password)
      
      if (success) {
        // VULNERABLE: Store remember me preference insecurely
        if (rememberMe) {
          localStorage.setItem('rememberMe', 'true')
          localStorage.setItem('lastUsername', username)
          // VULNERABLE: Store password hint
          localStorage.setItem('passwordHint', password.substring(0, 2) + '*'.repeat(password.length - 2))
        }
        
        toast.success('Login successful!')
        navigate(from, { replace: true })
      }
    } catch (error: any) {
      console.error('Login error:', error)
      toast.error('Login failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  // VULNERABLE: Populate fields from localStorage
  useEffect(() => {
    const remembered = localStorage.getItem('rememberMe')
    if (remembered === 'true') {
      const lastUsername = localStorage.getItem('lastUsername')
      if (lastUsername) {
        setUsername(lastUsername)
        setRememberMe(true)
      }
    }
  }, [])

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      {/* Matrix background effect */}
      <div className="matrix-bg" />
      
      <motion.div
        className="max-w-md w-full space-y-8"
        initial={{ opacity: 0, y: 50 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div>
          <motion.div
            className="mx-auto h-20 w-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center"
            whileHover={{ rotate: 360, scale: 1.1 }}
            transition={{ duration: 0.5 }}
          >
            <span className="text-white font-bold text-3xl">V</span>
          </motion.div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-white">
            Sign in to VulnCorp Enterprise
          </h2>
          <p className="mt-2 text-center text-sm text-gray-400">
            Welcome to the most advanced vulnerable enterprise application
          </p>
        </div>

        <motion.form
          className="mt-8 space-y-6"
          onSubmit={handleSubmit}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2, duration: 0.5 }}
        >
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <label htmlFor="username" className="sr-only">
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                required
                className="form-input rounded-t-md relative block w-full"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                // VULNERABLE: No input sanitization
                onInput={(e) => {
                  const input = e.target as HTMLInputElement
                  // VULNERABLE: Log user input
                  console.log('Username input:', input.value)
                }}
              />
            </div>
            <div className="relative">
              <label htmlFor="password" className="sr-only">
                Password
              </label>
              <input
                id="password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                required
                className="form-input rounded-b-md relative block w-full pr-10"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                // VULNERABLE: No password strength validation
                onInput={(e) => {
                  const input = e.target as HTMLInputElement
                  // VULNERABLE: Log password in console
                  if (process.env.NODE_ENV === 'development') {
                    console.log('Password input length:', input.value.length)
                  }
                }}
              />
              <button
                type="button"
                className="absolute inset-y-0 right-0 pr-3 flex items-center"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? (
                  <EyeSlashIcon className="h-5 w-5 text-gray-400" />
                ) : (
                  <EyeIcon className="h-5 w-5 text-gray-400" />
                )}
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <input
                id="remember-me"
                name="remember-me"
                type="checkbox"
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
              />
              <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-400">
                Remember me
              </label>
            </div>

            <div className="text-sm">
              <Link
                to="/forgot-password"
                className="font-medium text-blue-400 hover:text-blue-300"
              >
                Forgot your password?
              </Link>
            </div>
          </div>

          <div>
            <motion.button
              type="submit"
              disabled={loading}
              className="btn-primary w-full flex justify-center py-3 px-4 disabled:opacity-50 disabled:cursor-not-allowed"
              whileHover={{ scale: loading ? 1 : 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              {loading ? (
                <div className="loading-spinner"></div>
              ) : (
                'Sign in'
              )}
            </motion.button>
          </div>

          <div className="text-center">
            <span className="text-gray-400">Don't have an account? </span>
            <Link
              to="/register"
              className="font-medium text-blue-400 hover:text-blue-300"
            >
              Sign up
            </Link>
          </div>
        </motion.form>

        {/* VULNERABLE: Demo credentials display */}
        <motion.div
          className="mt-8 p-4 bg-gray-800 border border-gray-700 rounded-lg"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
        >
          <h3 className="text-lg font-semibold text-white mb-3">Demo Credentials</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-400">Admin:</span>
              <span className="text-white">admin / admin123</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Manager:</span>
              <span className="text-white">manager / manager123</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Employee:</span>
              <span className="text-white">employee / employee123</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Customer:</span>
              <span className="text-white">customer / customer123</span>
            </div>
          </div>
          <p className="text-xs text-red-400 mt-3">
            ⚠️ These credentials are for testing purposes only
          </p>
        </motion.div>

        {/* VULNERABLE: Debug information display */}
        {process.env.NODE_ENV === 'development' && (
          <motion.div
            className="mt-4 p-3 bg-red-900 border border-red-600 rounded-lg"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.7 }}
          >
            <h4 className="text-red-200 font-semibold mb-2">Debug Info (DEV ONLY)</h4>
            <div className="text-xs text-red-300 space-y-1">
              <div>From: {from}</div>
              <div>Timestamp: {new Date().toISOString()}</div>
              <div>User Agent: {navigator.userAgent.substring(0, 50)}...</div>
              <div>Local Storage Keys: {Object.keys(localStorage).join(', ')}</div>
            </div>
          </motion.div>
        )}
      </motion.div>
    </div>
  )
}

export default LoginPage

