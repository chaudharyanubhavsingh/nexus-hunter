/**
 * WebSocket Context Service
 * Real-time communication with intentional vulnerabilities
 */

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import io, { Socket } from 'socket.io-client'
import toast from 'react-hot-toast'

interface WebSocketContextType {
  socket: Socket | null
  connected: boolean
  sendMessage: (event: string, data: any) => void
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined)

export const WebSocketProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [socket, setSocket] = useState<Socket | null>(null)
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    // VULNERABLE: Connect without authentication
    const newSocket = io('ws://localhost:3002', {
      transports: ['websocket'],
      autoConnect: true
    })

    newSocket.on('connect', () => {
      console.log('WebSocket connected:', newSocket.id)
      setConnected(true)
      setSocket(newSocket)
    })

    newSocket.on('disconnect', () => {
      console.log('WebSocket disconnected')
      setConnected(false)
    })

    newSocket.on('message', (data) => {
      // VULNERABLE: Display raw messages without sanitization
      toast.success(`Message: ${JSON.stringify(data)}`)
    })

    return () => {
      newSocket.close()
    }
  }, [])

  const sendMessage = (event: string, data: any) => {
    if (socket && connected) {
      // VULNERABLE: Send data without validation
      socket.emit(event, data)
    }
  }

  return (
    <WebSocketContext.Provider value={{ socket, connected, sendMessage }}>
      {children}
    </WebSocketContext.Provider>
  )
}

export const useWebSocket = () => {
  const context = useContext(WebSocketContext)
  if (!context) {
    throw new Error('useWebSocket must be used within WebSocketProvider')
  }
  return context
}

