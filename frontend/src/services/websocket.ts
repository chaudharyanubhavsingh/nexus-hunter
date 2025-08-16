const WS_BASE_URL = (import.meta as any).env?.VITE_WS_URL || 'ws://localhost:8000/api/ws/';

export interface WebSocketMessage {
  type: 'connection_established' | 'connection_status' | 'echo' | 'subscription_confirmed' | 'unsubscription_confirmed' | 'pong' | 'error' | 'scan_update' | 'vulnerability_found' | 'system_status' | 'scan_completed' | 'scan_failed';
  data?: any;
  [key: string]: any;
}

export interface ScanUpdateData {
  scan_id: string;
  status: string;
  progress?: number;
  current_phase?: string;
  message?: string;
  [key: string]: any;
}

export interface VulnerabilityFoundData {
  scan_id: string;
  vulnerability: {
    title: string;
    severity: string;
    description?: string;
    [key: string]: any;
  };
  [key: string]: any;
}

class WebSocketService {
  private socket: WebSocket | null = null;
  private connectionStatus: 'connecting' | 'connected' | 'disconnected' | 'error' = 'disconnected';
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 3; // Keep at 3
  private reconnectDelay = 5000; // Reduced from 10 seconds to 5 seconds for better UX
  private listeners: Map<string, Array<(data: any) => void>> = new Map();
  private reconnectTimeout?: number;
  private isManualDisconnect = false;
  private isConnecting = false;
  private heartbeatInterval?: number; // Add heartbeat to maintain stable connection
  private bootId: string | null = null;

  constructor() {
    if (typeof WebSocket !== 'undefined' && typeof window !== 'undefined') {
      console.log('WebSocket service initialized (optimized for stability)');
    }
  }

  public connect() {
    if (this.isConnecting) {
      console.log('WebSocket connection already in progress');
      return;
    }

    if (this.socket?.readyState === WebSocket.OPEN) {
      console.log('WebSocket already connected');
      return;
    }

    if (this.socket?.readyState === WebSocket.CONNECTING) {
      console.log('WebSocket already connecting');
      return;
    }

    this.isConnecting = true;
    this.isManualDisconnect = false;

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('Resetting reconnection attempts for manual connect');
      this.reconnectAttempts = 0;
    }

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.warn('WebSocket: Max connection attempts reached. Call connect() manually to retry.');
      this.isConnecting = false;
      return;
    }

    this.connectionStatus = 'connecting';
    console.log(`WebSocket: Attempting to connect (${this.reconnectAttempts + 1}/${this.maxReconnectAttempts})`);
    
    try {
      this.socket = new WebSocket(WS_BASE_URL);
    } catch (error) {
      console.error('WebSocket: Failed to create connection:', error);
      this.connectionStatus = 'error';
      this.isConnecting = false;
      this.scheduleReconnect();
      return;
    }

    this.socket.onopen = () => {
      console.log('WebSocket connected successfully');
      this.connectionStatus = 'connected';
      this.reconnectAttempts = 0;
      this.isManualDisconnect = false;
      this.isConnecting = false;
      this.startHeartbeat();
      this.notifyStatusChange();
    };

    this.socket.onclose = (event) => {
      console.log(`WebSocket disconnected: ${event.code} ${event.reason || 'No reason'}`);
      this.connectionStatus = 'disconnected';
      this.isConnecting = false;
      this.stopHeartbeat();
      this.notifyStatusChange();
      
      if (event.code !== 1000 && !this.isManualDisconnect && this.reconnectAttempts < this.maxReconnectAttempts) {
        this.scheduleReconnect();
      }
    };

    this.socket.onerror = (error) => {
      console.error('WebSocket connection error:', error);
      this.connectionStatus = 'error';
      this.isConnecting = false;
      this.notifyStatusChange();
    };

    this.socket.onmessage = (event) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data);
        console.log('WebSocket message received:', message);
        if (message && typeof message.type === 'string') {
          if ((message as any).boot_id) {
            this.bootId = (message as any).boot_id as string;
          }
          const payload = (message.data !== undefined) ? message.data : message;
          this.notifyListeners(message.type, payload);
          if (message.type === 'connection_status') {
            this.notifyListeners('connection_boot', { boot_id: this.bootId });
          }
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
    this.reconnectTimeout = window.setTimeout(() => {
      console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      this.connect();
    }, this.reconnectDelay);
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatInterval = window.setInterval(() => {
      if (this.socket?.readyState === WebSocket.OPEN) {
        this.socket.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
      }
    }, 30000);
  }

  private stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = undefined;
    }
  }

  private notifyListeners(eventType: string, data: any) {
    const typeListeners = this.listeners.get(eventType);
    if (typeListeners) {
      typeListeners.forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error(`Error in WebSocket listener for ${eventType}:`, error);
        }
      });
    }
  }

  private notifyStatusChange() {
    this.notifyListeners('connection_status', {
      status: this.connectionStatus,
      boot_id: this.bootId,
      timestamp: new Date().toISOString()
    });
  }

  // Public methods
  subscribe(eventType: string, callback: (data: any) => void) {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, []);
    }
    this.listeners.get(eventType)!.push(callback);

    return () => {
      const typeListeners = this.listeners.get(eventType);
      if (typeListeners) {
        const index = typeListeners.indexOf(callback);
        if (index > -1) {
          typeListeners.splice(index, 1);
        }
        if (typeListeners.length === 0) {
          this.listeners.delete(eventType);
        }
      }
    };
  }

  unsubscribe(eventType: string, callback: (data: any) => void) {
    const typeListeners = this.listeners.get(eventType);
    if (typeListeners) {
      const index = typeListeners.indexOf(callback);
      if (index > -1) {
        typeListeners.splice(index, 1);
      }
      if (typeListeners.length === 0) {
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
      if (data && (data as any).scan_id === scanId) {
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

  getBootId() {
    return this.bootId;
  }

  // Cleanup
  public disconnect() {
    console.log('WebSocket: Manual disconnect requested');
    this.isManualDisconnect = true;
    this.stopHeartbeat();
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }
    if (this.socket) {
      this.socket.close(1000, 'Manual disconnect');
      this.socket = null;
    }
    this.connectionStatus = 'disconnected';
    this.notifyStatusChange();
  }

  public reconnect() {
    console.log('WebSocket: Manual reconnect requested');
    this.isManualDisconnect = false;
    this.reconnectAttempts = 0;
    this.connect();
  }
}

export const webSocketService = new WebSocketService();
export default webSocketService; 