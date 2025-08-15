const WS_BASE_URL = (import.meta as any).env?.VITE_WS_URL || 'ws://localhost:8000/api/ws';

export interface WebSocketMessage {
  type: 'scan_update' | 'vulnerability_found' | 'system_status' | 'scan_completed';
  data: any;
  timestamp: string;
}

export interface ScanUpdateData {
  scan_id: string;
  status: string;
  progress: number;
  current_phase: string;
  message?: string;
}

export interface VulnerabilityFoundData {
  scan_id: string;
  vulnerability: {
    title: string;
    severity: string;
    description: string;
  };
}

class WebSocketService {
  private socket: WebSocket | null = null;
  private listeners: Map<string, Set<(data: any) => void>> = new Map();
  private connectionStatus: 'connecting' | 'connected' | 'disconnected' | 'error' = 'disconnected';
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectInterval = 5000;

  constructor() {
    this.connect();
  }

  private connect() {
    if (this.socket?.readyState === WebSocket.OPEN) {
      return;
    }

    this.connectionStatus = 'connecting';
    this.socket = new WebSocket(WS_BASE_URL);

    this.socket.onopen = () => {
      console.log('WebSocket connected');
      this.connectionStatus = 'connected';
      this.reconnectAttempts = 0;
      this.notifyStatusChange();
    };

    this.socket.onclose = () => {
      console.log('WebSocket disconnected');
      this.connectionStatus = 'disconnected';
      this.notifyStatusChange();
      this.scheduleReconnect();
    };

    this.socket.onerror = (error) => {
      console.error('WebSocket connection error:', error);
      this.connectionStatus = 'error';
      this.notifyStatusChange();
      this.scheduleReconnect();
    };

    this.socket.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.type && message.data) {
          this.notifyListeners(message.type, message.data);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };
  }

  private scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      return;
    }

    this.reconnectAttempts++;
    setTimeout(() => {
      console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      this.connect();
    }, this.reconnectInterval);
  }

  private notifyListeners(type: string, data: any) {
    const typeListeners = this.listeners.get(type);
    if (typeListeners) {
      typeListeners.forEach(callback => callback(data));
    }

    // Also notify general listeners
    const generalListeners = this.listeners.get('*');
    if (generalListeners) {
      generalListeners.forEach(callback => callback({ type, data }));
    }
  }

  private notifyStatusChange() {
    this.notifyListeners('connection_status', {
      status: this.connectionStatus,
      timestamp: new Date().toISOString()
    });
  }

  // Public methods
  subscribe(eventType: string, callback: (data: any) => void) {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set());
    }
    this.listeners.get(eventType)!.add(callback);

    // Return unsubscribe function
    return () => {
      const typeListeners = this.listeners.get(eventType);
      if (typeListeners) {
        typeListeners.delete(callback);
        if (typeListeners.size === 0) {
          this.listeners.delete(eventType);
        }
      }
    };
  }

  unsubscribe(eventType: string, callback: (data: any) => void) {
    const typeListeners = this.listeners.get(eventType);
    if (typeListeners) {
      typeListeners.delete(callback);
      if (typeListeners.size === 0) {
        this.listeners.delete(eventType);
      }
    }
  }

  // Subscribe to scan-specific updates
  subscribeScan(scanId: string, callback: (data: ScanUpdateData) => void) {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify({ type: 'subscribe_scan', scan_id: scanId }));
    }
    return this.subscribe('scan_update', (data: ScanUpdateData) => {
      if (data.scan_id === scanId) {
        callback(data);
      }
    });
  }

  unsubscribeScan(scanId: string) {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify({ type: 'unsubscribe_scan', scan_id: scanId }));
    }
  }

  // Send messages
  sendMessage(type: string, data: any) {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify({ type, data }));
    } else {
      console.warn('WebSocket not connected, cannot send message');
    }
  }

  // Getters
  getConnectionStatus() {
    return this.connectionStatus;
  }

  isConnected() {
    return this.connectionStatus === 'connected';
  }

  // Cleanup
  disconnect() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.listeners.clear();
    this.connectionStatus = 'disconnected';
  }
}

// Create singleton instance
export const webSocketService = new WebSocketService();
export default webSocketService; 