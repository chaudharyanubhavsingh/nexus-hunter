/**
 * Notification Center Component
 * Display system notifications and alerts
 */

import React from 'react'
import { motion } from 'framer-motion'
import { XMarkIcon, ExclamationTriangleIcon, InformationCircleIcon } from '@heroicons/react/24/outline'

interface NotificationCenterProps {
  onClose: () => void
}

const NotificationCenter: React.FC<NotificationCenterProps> = ({ onClose }) => {
  const notifications = [
    {
      id: 1,
      type: 'warning',
      title: 'Security Alert',
      message: 'SQL injection attempt detected',
      timestamp: '2 minutes ago'
    },
    {
      id: 2,
      type: 'info',
      title: 'System Update',
      message: 'VulnCorp Enterprise updated to v1.0.0',
      timestamp: '1 hour ago'
    },
    {
      id: 3,
      type: 'warning',
      title: 'File Upload',
      message: 'Suspicious file uploaded: shell.php',
      timestamp: '3 hours ago'
    }
  ]

  return (
    <div className="p-4 z-50">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-semibold text-white">Notifications</h3>
        <button onClick={onClose} className="text-gray-400 hover:text-white">
          <XMarkIcon className="w-5 h-5" />
        </button>
      </div>
      
      <div className="space-y-3">
        {notifications.map((notification, index) => (
          <motion.div
            key={notification.id}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.1 }}
            className="flex items-start space-x-3 p-3 bg-gray-700 rounded-lg"
          >
            {notification.type === 'warning' ? (
              <ExclamationTriangleIcon className="w-5 h-5 text-yellow-400 mt-0.5" />
            ) : (
              <InformationCircleIcon className="w-5 h-5 text-blue-400 mt-0.5" />
            )}
            <div className="flex-1">
              <p className="text-white font-medium text-sm">{notification.title}</p>
              <p className="text-gray-300 text-xs">{notification.message}</p>
              <p className="text-gray-400 text-xs mt-1">{notification.timestamp}</p>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  )
}

export default NotificationCenter

