// Socket.IO Event Types

// Order Events
interface OrderSubscribeEvent {
  orderId: string;
}

interface OrderUpdateEvent {
  orderId: string;
  status: 'pending' | 'processing' | 'shipped' | 'delivered' | 'cancelled';
  timestamp: Date;
}

// Cart Events
interface CartItem {
  productId: string;
  quantity: number;
  price: number;
}

interface CartUpdateEvent {
  userId: string;
  items: CartItem[];
  total: number;
}

interface CartStockWarning {
  productId: string;
  availableStock: number;
}

// Product Events
interface ProductStockUpdate {
  productId: string;
  newStock: number;
  updatedAt: Date;
}

// User Events
interface UserStatus {
  userId: string;
  status: 'online' | 'offline';
  lastSeen: Date;
}

// Socket.IO Client to Server Events
interface ClientToServerEvents {
  'order:subscribe': (data: OrderSubscribeEvent) => void;
  'cart:update': (data: CartUpdateEvent) => void;
  'product:watch': (productId: string) => void;
}

// Socket.IO Server to Client Events
interface ServerToClientEvents {
  'order:updated': (data: OrderUpdateEvent) => void;
  'cart:updated': (data: CartUpdateEvent) => void;
  'cart:stockWarning': (data: CartStockWarning) => void;
  'product:stockUpdate': (data: ProductStockUpdate) => void;
  'error': (error: { message: string }) => void;
}

// Socket.IO Inter-Server Events
interface InterServerEvents {
  ping: () => void;
}

// Socket.IO Socket Data
interface SocketData {
  user: {
    id: string;
    role: string;
    email: string;
  };
}

export {
  OrderSubscribeEvent,
  OrderUpdateEvent,
  CartItem,
  CartUpdateEvent,
  CartStockWarning,
  ProductStockUpdate,
  UserStatus,
  ClientToServerEvents,
  ServerToClientEvents,
  InterServerEvents,
  SocketData
};