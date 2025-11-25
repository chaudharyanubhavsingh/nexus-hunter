/**
 * Protected Route Component
 * Route protection with authentication check
 */

import React, { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '@services/AuthContext'

interface ProtectedRouteProps {
  children: ReactNode
  requiredRole?: string
  requiredPermission?: string
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  requiredRole,
  requiredPermission 
}) => {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="loading-spinner"></div>
      </div>
    )
  }

  if (!user) {
    // Redirect to login page with return url
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  // VULNERABLE: Client-side role/permission checks only
  if (requiredRole && user.role !== requiredRole) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center text-white">
          <h2 className="text-2xl font-bold mb-4">Access Denied</h2>
          <p>You don't have the required role: {requiredRole}</p>
          <p className="text-sm text-gray-400 mt-2">Your role: {user.role}</p>
        </div>
      </div>
    )
  }

  if (requiredPermission && !user.permissions?.includes(requiredPermission)) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center text-white">
          <h2 className="text-2xl font-bold mb-4">Access Denied</h2>
          <p>You don't have the required permission: {requiredPermission}</p>
        </div>
      </div>
    )
  }

  return <>{children}</>
}

export default ProtectedRoute

