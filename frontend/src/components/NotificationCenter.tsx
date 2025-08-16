import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bell, X, AlertTriangle, CheckCircle, Info, Zap } from 'lucide-react';

interface Notification {
  id: string;
  type: string;
  priority: string;
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  data?: any;
}

const NotificationCenter: React.FC = () => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);

  useEffect(() => {
    // Listen for WebSocket notifications
    const handleWebSocketMessage = (event: MessageEvent) => {
      try {
        const message = JSON.parse(event.data);
        if (message.type === 'notification') {
          const notification = message.data;
          addNotification(notification);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    // Connect to WebSocket
    const ws = new WebSocket('ws://localhost:8000/api/ws/');
    ws.addEventListener('message', handleWebSocketMessage);

    return () => {
      ws.close();
    };
  }, []);

  const addNotification = (notification: Notification) => {
    setNotifications(prev => [notification, ...prev.slice(0, 49)]); // Keep only last 50
    if (!notification.read) {
      setUnreadCount(prev => prev + 1);
    }
  };

  const markAsRead = (notificationId: string) => {
    setNotifications(prev =>
      prev.map(n =>
        n.id === notificationId ? { ...n, read: true } : n
      )
    );
    setUnreadCount(prev => Math.max(0, prev - 1));
  };

  const markAllAsRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
    setUnreadCount(0);
  };

  const clearAll = () => {
    setNotifications([]);
    setUnreadCount(0);
  };

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'scan_completed':
        return CheckCircle;
      case 'scan_failed':
        return AlertTriangle;
      case 'vulnerability_found':
      case 'critical_vulnerability':
        return AlertTriangle;
      case 'system_alert':
        return Zap;
      default:
        return Info;
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical':
        return 'neon-red';
      case 'high':
        return 'neon-orange';
      case 'medium':
        return 'neon-cyan';
      case 'low':
        return 'cyber-gray';
      default:
        return 'cyber-gray';
    }
  };

  return (
    <div className="relative">
      {/* Notification Bell */}
      <motion.button
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 text-cyber-white hover:text-neon-cyan transition-colors"
      >
        <Bell size={24} />
        {unreadCount > 0 && (
          <motion.span
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            className="absolute -top-1 -right-1 bg-neon-red text-cyber-black text-xs font-bold rounded-full w-5 h-5 flex items-center justify-center"
          >
            {unreadCount > 9 ? '9+' : unreadCount}
          </motion.span>
        )}
      </motion.button>

      {/* Notification Panel */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -10, scale: 0.95 }}
            className="absolute right-0 top-full mt-2 w-96 bg-cyber-black border border-cyber-gray rounded-lg shadow-2xl z-50"
          >
            {/* Header */}
            <div className="p-4 border-b border-cyber-gray">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-bold text-cyber-white">Notifications</h3>
                <div className="flex items-center gap-2">
                  {unreadCount > 0 && (
                    <button
                      onClick={markAllAsRead}
                      className="text-xs text-neon-cyan hover:text-cyber-white transition-colors"
                    >
                      Mark all read
                    </button>
                  )}
                  <button
                    onClick={clearAll}
                    className="text-xs text-cyber-gray hover:text-cyber-white transition-colors"
                  >
                    Clear all
                  </button>
                  <button
                    onClick={() => setIsOpen(false)}
                    className="text-cyber-gray hover:text-cyber-white transition-colors"
                  >
                    <X size={18} />
                  </button>
                </div>
              </div>
            </div>

            {/* Notifications List */}
            <div className="max-h-96 overflow-y-auto">
              {notifications.length === 0 ? (
                <div className="p-4 text-center text-cyber-muted">
                  <Bell className="mx-auto mb-2 opacity-50" size={32} />
                  <p>No notifications yet</p>
                </div>
              ) : (
                <div className="divide-y divide-cyber-gray divide-opacity-30">
                  {notifications.map((notification) => {
                    const Icon = getNotificationIcon(notification.type);
                    const priorityColor = getPriorityColor(notification.priority);

                    return (
                      <motion.div
                        key={notification.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        className={`p-4 hover:bg-cyber-gray hover:bg-opacity-10 transition-colors cursor-pointer ${
                          !notification.read ? 'bg-neon-cyan bg-opacity-5' : ''
                        }`}
                        onClick={() => markAsRead(notification.id)}
                      >
                        <div className="flex items-start gap-3">
                          <div className={`p-1 bg-${priorityColor} bg-opacity-20 rounded`}>
                            <Icon className={`text-${priorityColor}`} size={16} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between mb-1">
                              <h4 className={`text-sm font-medium ${
                                notification.read ? 'text-cyber-muted' : 'text-cyber-white'
                              }`}>
                                {notification.title}
                              </h4>
                              {!notification.read && (
                                <div className="w-2 h-2 bg-neon-cyan rounded-full flex-shrink-0" />
                              )}
                            </div>
                            <p className={`text-xs ${
                              notification.read ? 'text-cyber-muted' : 'text-cyber-gray'
                            }`}>
                              {notification.message}
                            </p>
                            <p className="text-xs text-cyber-muted mt-1">
                              {new Date(notification.timestamp).toLocaleTimeString()}
                            </p>
                          </div>
                        </div>
                      </motion.div>
                    );
                  })}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default NotificationCenter; 