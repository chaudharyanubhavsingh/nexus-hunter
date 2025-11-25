/**
 * Main Layout Component
 * Enterprise dashboard layout with navigation and sidebar
 */

import React, { useState } from 'react'
import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  HomeIcon,
  UsersIcon,
  ShoppingBagIcon,
  ClipboardDocumentListIcon,
  CurrencyDollarIcon,
  UserGroupIcon,
  PhoneIcon,
  CogIcon,
  BeakerIcon,
  UserCircleIcon,
  ArrowRightOnRectangleIcon,
  Bars3Icon,
  XMarkIcon,
  BellIcon,
  MagnifyingGlassIcon,
} from '@heroicons/react/24/outline'

import { useAuth } from '@services/AuthContext'
import NotificationCenter from '@components/NotificationCenter'

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: HomeIcon },
  { name: 'Users', href: '/users', icon: UsersIcon },
  { name: 'Products', href: '/products', icon: ShoppingBagIcon },
  { name: 'Orders', href: '/orders', icon: ClipboardDocumentListIcon },
  { name: 'Finance', href: '/finance', icon: CurrencyDollarIcon },
  { name: 'Human Resources', href: '/hr', icon: UserGroupIcon },
  { name: 'CRM', href: '/crm', icon: PhoneIcon },
  { name: 'Admin Panel', href: '/admin', icon: CogIcon, requiresAdmin: true },
  { name: 'Vulnerability Lab', href: '/vulnerability-lab', icon: BeakerIcon, danger: true },
]

const Layout: React.FC = () => {
  const { user, logout, isAdmin } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [showNotifications, setShowNotifications] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (searchQuery.trim()) {
      // VULNERABLE: Direct search without sanitization
      navigate(`/search?q=${encodeURIComponent(searchQuery)}`)
    }
  }

  const filteredNavigation = navigation.filter(item => {
    if (item.requiresAdmin && !isAdmin()) {
      return false
    }
    return true
  })

  return (
    <div className="h-screen flex overflow-hidden bg-gray-900">
      {/* Matrix background effect */}
      <div className="matrix-bg" />
      
      {/* Mobile sidebar backdrop */}
      <AnimatePresence>
        {sidebarOpen && (
          <motion.div
            className="fixed inset-0 z-40 lg:hidden"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <div
              className="absolute inset-0 bg-gray-600 bg-opacity-75"
              onClick={() => setSidebarOpen(false)}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <AnimatePresence>
        <motion.div
          className={`fixed inset-y-0 left-0 z-50 w-64 bg-gray-800 transform ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          } lg:translate-x-0 lg:static lg:inset-0 transition duration-300 ease-in-out lg:transition-none`}
          initial={false}
          animate={{ x: sidebarOpen ? 0 : -256 }}
        >
          <div className="flex items-center justify-between flex-shrink-0 px-4 py-4">
            <Link to="/dashboard" className="flex items-center">
              <motion.div
                className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center mr-3"
                whileHover={{ rotate: 360 }}
                transition={{ duration: 0.5 }}
              >
                <span className="text-white font-bold text-lg">V</span>
              </motion.div>
              <span className="text-xl font-bold text-white">VulnCorp</span>
            </Link>
            <button
              className="lg:hidden text-gray-400 hover:text-white"
              onClick={() => setSidebarOpen(false)}
            >
              <XMarkIcon className="w-6 h-6" />
            </button>
          </div>

          <div className="flex-1 flex flex-col overflow-y-auto">
            <nav className="flex-1 px-2 py-4 space-y-1">
              {filteredNavigation.map((item) => {
                const isActive = location.pathname === item.href
                return (
                  <Link
                    key={item.name}
                    to={item.href}
                    className={`nav-link group ${isActive ? 'active' : ''} ${
                      item.danger ? 'hover:bg-red-600' : ''
                    }`}
                    onClick={() => setSidebarOpen(false)}
                  >
                    <item.icon
                      className={`mr-3 flex-shrink-0 h-5 w-5 ${
                        isActive
                          ? 'text-white'
                          : item.danger
                          ? 'text-red-400 group-hover:text-white'
                          : 'text-gray-400 group-hover:text-white'
                      }`}
                    />
                    <span className={item.danger ? 'text-red-400 group-hover:text-white' : ''}>
                      {item.name}
                    </span>
                    {item.danger && (
                      <span className="ml-auto text-xs bg-red-600 text-white px-2 py-1 rounded">
                        DANGER
                      </span>
                    )}
                  </Link>
                )
              })}
            </nav>

            {/* User section */}
            <div className="flex-shrink-0 px-2 py-4 border-t border-gray-700">
              <div className="flex items-center">
                <img
                  className="inline-block h-10 w-10 rounded-full"
                  src={user?.avatar || `https://ui-avatars.com/api/?name=${user?.firstName || user?.username}&background=3b82f6&color=fff`}
                  alt={user?.username}
                />
                <div className="ml-3 flex-1">
                  <p className="text-sm font-medium text-white">
                    {user?.firstName ? `${user.firstName} ${user.lastName}` : user?.username}
                  </p>
                  <p className="text-xs text-gray-400 capitalize">{user?.role}</p>
                </div>
              </div>
              <div className="mt-3 space-y-1">
                <Link
                  to="/profile"
                  className="nav-link text-sm"
                  onClick={() => setSidebarOpen(false)}
                >
                  <UserCircleIcon className="mr-3 h-4 w-4" />
                  Profile
                </Link>
                <button
                  onClick={logout}
                  className="nav-link text-sm w-full text-left text-red-400 hover:text-white hover:bg-red-600"
                >
                  <ArrowRightOnRectangleIcon className="mr-3 h-4 w-4" />
                  Sign out
                </button>
              </div>
            </div>
          </div>
        </motion.div>
      </AnimatePresence>

      {/* Main content area */}
      <div className="flex-1 overflow-hidden flex flex-col">
        {/* Top navigation */}
        <header className="bg-gray-800 border-b border-gray-700 flex-shrink-0">
          <div className="px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-16">
              <div className="flex items-center">
                <button
                  className="lg:hidden text-gray-400 hover:text-white mr-4"
                  onClick={() => setSidebarOpen(true)}
                >
                  <Bars3Icon className="w-6 h-6" />
                </button>

                {/* Search */}
                <form onSubmit={handleSearch} className="flex-1 max-w-lg">
                  <div className="relative">
                    <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search users, products, orders..."
                      className="form-input pl-10 pr-4 py-2 w-full max-w-md"
                      // VULNERABLE: No input validation or sanitization
                    />
                  </div>
                </form>
              </div>

              <div className="flex items-center space-x-4">
                {/* Notifications */}
                <div className="relative">
                  <button
                    className="text-gray-400 hover:text-white p-2 rounded-full hover:bg-gray-700"
                    onClick={() => setShowNotifications(!showNotifications)}
                  >
                    <BellIcon className="w-6 h-6" />
                    <span className="absolute top-0 right-0 block h-2 w-2 rounded-full bg-red-400 ring-2 ring-gray-800"></span>
                  </button>

                  <AnimatePresence>
                    {showNotifications && (
                      <motion.div
                        initial={{ opacity: 0, scale: 0.95, y: -10 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.95, y: -10 }}
                        className="absolute right-0 mt-2 w-80 bg-gray-800 border border-gray-700 rounded-lg shadow-lg z-50"
                      >
                        <NotificationCenter onClose={() => setShowNotifications(false)} />
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>

                {/* User menu */}
                <Link
                  to="/profile"
                  className="flex items-center space-x-3 text-gray-400 hover:text-white p-2 rounded-lg hover:bg-gray-700"
                >
                  <img
                    className="h-8 w-8 rounded-full"
                    src={user?.avatar || `https://ui-avatars.com/api/?name=${user?.firstName || user?.username}&background=3b82f6&color=fff`}
                    alt={user?.username}
                  />
                  <span className="hidden md:block text-sm font-medium">
                    {user?.firstName || user?.username}
                  </span>
                </Link>
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto focus:outline-none">
          <div className="py-6">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              {/* VULNERABLE: Render outlet without proper error boundaries */}
              <Outlet />
            </div>
          </div>
        </main>

        {/* Footer with system info (Information Disclosure) */}
        <footer className="bg-gray-800 border-t border-gray-700 px-4 py-3">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <div>
              VulnCorp Enterprise v1.0.0 | Build: {Date.now()}
            </div>
            <div className="flex space-x-4">
              <span>Server: {window.location.hostname}</span>
              <span>User: {user?.username}</span>
              <span>Role: {user?.role}</span>
              <span>Session: {localStorage.getItem('auth-token')?.slice(-8)}</span>
            </div>
          </div>
        </footer>
      </div>
    </div>
  )
}

export default Layout

