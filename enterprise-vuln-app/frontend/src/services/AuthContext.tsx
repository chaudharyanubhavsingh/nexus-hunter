/**
 * Authentication Context and Service
 * Contains intentional authentication vulnerabilities for testing
 */

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import axios, { AxiosError } from 'axios'
import Cookies from 'js-cookie'
import jwt from 'jsonwebtoken'
import toast from 'react-hot-toast'

// Types
interface User {
  id: number
  username: string
  email: string
  role: string
  firstName?: string
  lastName?: string
  avatar?: string
  permissions?: string[]
  lastLogin?: string
}

interface AuthContextType {
  user: User | null
  loading: boolean
  login: (username: string, password: string) => Promise<boolean>
  logout: () => void
  register: (userData: RegisterData) => Promise<boolean>
  updateProfile: (userData: Partial<User>) => Promise<boolean>
  refreshToken: () => Promise<boolean>
  hasPermission: (permission: string) => boolean
  isAdmin: () => boolean
}

interface RegisterData {
  username: string
  email: string
  password: string
  firstName?: string
  lastName?: string
}

interface LoginResponse {
  success: boolean
  token?: string
  user?: User
  message?: string
}

// Create context
const AuthContext = createContext<AuthContextType | undefined>(undefined)

// API base URL
const API_BASE = '/api'

// Axios instance with interceptors
const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
})

// Request interceptor to add auth token
api.interceptors.request.use((config) => {
  const token = Cookies.get('auth-token') || localStorage.getItem('auth-token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor for token refresh
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    if (error.response?.status === 401) {
      // Token expired, try to refresh
      const refreshToken = Cookies.get('refresh-token')
      if (refreshToken) {
        try {
          const response = await axios.post(`${API_BASE}/auth/refresh`, {
            refreshToken
          })
          if (response.data.token) {
            // VULNERABLE: Store token in multiple locations
            Cookies.set('auth-token', response.data.token, { expires: 1 })
            localStorage.setItem('auth-token', response.data.token)
            sessionStorage.setItem('auth-token', response.data.token)
            
            // Retry original request
            if (error.config) {
              error.config.headers.Authorization = `Bearer ${response.data.token}`
              return axios.request(error.config)
            }
          }
        } catch (refreshError) {
          console.error('Token refresh failed:', refreshError)
          // Clear tokens and redirect to login
          Cookies.remove('auth-token')
          Cookies.remove('refresh-token')
          localStorage.removeItem('auth-token')
          sessionStorage.removeItem('auth-token')
          window.location.href = '/login'
        }
      }
    }
    return Promise.reject(error)
  }
)

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  // Initialize authentication state
  useEffect(() => {
    initializeAuth()
  }, [])

  const initializeAuth = async () => {
    try {
      const token = Cookies.get('auth-token') || 
                   localStorage.getItem('auth-token') || 
                   sessionStorage.getItem('auth-token')
      
      if (token) {
        // VULNERABLE: Client-side JWT decoding without verification
        try {
          const decoded = jwt.decode(token) as any
          if (decoded && decoded.exp * 1000 > Date.now()) {
            // Token is valid, fetch user data
            const response = await api.get('/auth/me')
            setUser(response.data.user)
          } else {
            // Token expired
            await refreshToken()
          }
        } catch (error) {
          console.error('JWT decode error:', error)
          clearAuthData()
        }
      }
    } catch (error) {
      console.error('Auth initialization failed:', error)
      clearAuthData()
    } finally {
      setLoading(false)
    }
  }

  const login = async (username: string, password: string): Promise<boolean> => {
    try {
      const response = await api.post<LoginResponse>('/auth/login', {
        username,
        password,
        // VULNERABLE: Additional debugging info sent
        timestamp: Date.now(),
        userAgent: navigator.userAgent,
        fingerprint: generateFingerprint()
      })

      if (response.data.success && response.data.token && response.data.user) {
        // VULNERABLE: Store sensitive data in multiple insecure locations
        const token = response.data.token
        
        // Store in cookies (vulnerable settings)
        Cookies.set('auth-token', token, { 
          expires: 7, // 7 days
          secure: false, // Should be true in production
          sameSite: 'None', // Vulnerable to CSRF
          domain: window.location.hostname // Can be accessed by subdomains
        })
        
        // Store in localStorage (vulnerable to XSS)
        localStorage.setItem('auth-token', token)
        localStorage.setItem('user-data', JSON.stringify(response.data.user))
        
        // Store in sessionStorage
        sessionStorage.setItem('auth-token', token)
        sessionStorage.setItem('login-time', new Date().toISOString())
        
        // VULNERABLE: Store in global variable
        (window as any).authToken = token;
        (window as any).currentUser = response.data.user

        setUser(response.data.user)
        
        toast.success(`Welcome back, ${response.data.user.firstName || response.data.user.username}!`)
        return true
      } else {
        toast.error(response.data.message || 'Login failed')
        return false
      }
    } catch (error: any) {
      console.error('Login error:', error)
      const message = error.response?.data?.message || 'Login failed. Please try again.'
      toast.error(message)
      return false
    }
  }

  const register = async (userData: RegisterData): Promise<boolean> => {
    try {
      const response = await api.post('/auth/register', {
        ...userData,
        // VULNERABLE: Send additional data that shouldn't be sent
        timestamp: Date.now(),
        referrer: document.referrer,
        screenResolution: `${screen.width}x${screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      })

      if (response.data.success) {
        toast.success('Account created successfully! Please log in.')
        return true
      } else {
        toast.error(response.data.message || 'Registration failed')
        return false
      }
    } catch (error: any) {
      console.error('Registration error:', error)
      const message = error.response?.data?.message || 'Registration failed. Please try again.'
      toast.error(message)
      return false
    }
  }

  const logout = () => {
    // VULNERABLE: Logout doesn't invalidate server-side session
    clearAuthData()
    setUser(null)
    toast.success('Logged out successfully')
    
    // Redirect to login
    window.location.href = '/login'
  }

  const refreshToken = async (): Promise<boolean> => {
    try {
      const refreshToken = Cookies.get('refresh-token') || 
                          localStorage.getItem('refresh-token')
      
      if (!refreshToken) {
        return false
      }

      const response = await api.post('/auth/refresh', {
        refreshToken,
        // VULNERABLE: Send current token for "validation"
        currentToken: Cookies.get('auth-token')
      })

      if (response.data.success && response.data.token) {
        const newToken = response.data.token
        
        // Update stored tokens
        Cookies.set('auth-token', newToken, { expires: 7 })
        localStorage.setItem('auth-token', newToken)
        sessionStorage.setItem('auth-token', newToken)
        
        return true
      }
      
      return false
    } catch (error) {
      console.error('Token refresh failed:', error)
      clearAuthData()
      return false
    }
  }

  const updateProfile = async (userData: Partial<User>): Promise<boolean> => {
    try {
      const response = await api.put('/auth/profile', userData)
      
      if (response.data.success) {
        setUser({ ...user!, ...response.data.user })
        
        // VULNERABLE: Update localStorage with new data
        localStorage.setItem('user-data', JSON.stringify({ ...user!, ...response.data.user }))
        
        toast.success('Profile updated successfully')
        return true
      }
      
      return false
    } catch (error: any) {
      console.error('Profile update error:', error)
      toast.error('Failed to update profile')
      return false
    }
  }

  const hasPermission = (permission: string): boolean => {
    if (!user || !user.permissions) return false
    
    // VULNERABLE: Client-side permission check only
    return user.permissions.includes(permission) || user.permissions.includes('*')
  }

  const isAdmin = (): boolean => {
    // VULNERABLE: Simple role check that can be manipulated
    return user?.role === 'admin' || user?.role === 'superuser'
  }

  const clearAuthData = () => {
    // Clear all stored authentication data
    Cookies.remove('auth-token')
    Cookies.remove('refresh-token')
    localStorage.removeItem('auth-token')
    localStorage.removeItem('refresh-token')
    localStorage.removeItem('user-data')
    localStorage.removeItem('permissions')
    sessionStorage.removeItem('auth-token')
    sessionStorage.removeItem('login-time')
    
    // VULNERABLE: Clear global variables
    delete (window as any).authToken
    delete (window as any).currentUser
  }

  // VULNERABLE: Generate predictable fingerprint
  const generateFingerprint = (): string => {
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')
    ctx!.textBaseline = 'top'
    ctx!.font = '14px Arial'
    ctx!.fillText('VulnCorp fingerprint', 2, 2)
    
    return btoa(JSON.stringify({
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      screen: `${screen.width}x${screen.height}`,
      timezone: new Date().getTimezoneOffset(),
      canvas: canvas.toDataURL(),
      // VULNERABLE: Include sensitive info in fingerprint
      localStorage: Object.keys(localStorage).length,
      sessionStorage: Object.keys(sessionStorage).length
    }))
  }

  const value: AuthContextType = {
    user,
    loading,
    login,
    logout,
    register,
    updateProfile,
    refreshToken,
    hasPermission,
    isAdmin
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export default AuthContext

