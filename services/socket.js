import { Server } from 'socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import { createClient } from 'redis';
import { createRateLimiter } from '@socket.io/rate-limiter';
import { verifyToken } from '../middleware/auth.js';
import Order from '../models/order.js';
import Cart from '../models/cart.js';
import User from '../models/user.js';

class SocketService {
  constructor(httpServer) {
    this.io = null;
    this.pubClient = null;
    this.subClient = null;
    this.initialize(httpServer);
  }

  async initialize(httpServer) {
    // Initialize Redis clients
    this.pubClient = createClient({ url: process.env.REDIS_URL });
    this.subClient = this.pubClient.duplicate();

    // Initialize Socket.IO with configuration
    this.io = new Server(httpServer, {
      cors: {
        origin: process.env.NODE_ENV === 'production'
          ? [process.env.FRONTEND_URL, 'https://shopify-dashboard-woad.vercel.app']
          : ['http://localhost:8080', 'http://127.0.0.1:8080', 'http://localhost:5173', 'http://127.0.0.1:5173'],
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        credentials: true
      },
      pingTimeout: 60000,
      pingInterval: 25000,
      maxHttpBufferSize: 1e6 // 1MB
    });

    // Apply rate limiter
    const rateLimiter = createRateLimiter({
      points: 10,
      duration: 1,
    });
    this.io.use(rateLimiter);

    // Connect Redis adapter
    try {
      await Promise.all([
        this.pubClient.connect(),
        this.subClient.connect()
      ]);
      this.io.adapter(createAdapter(this.pubClient, this.subClient));
      console.log('Socket.IO Redis adapter connected');
    } catch (err) {
      console.warn('Failed to connect Socket.IO Redis adapter:', err.message);
      console.log('Falling back to in-memory adapter');
    }

    // Add authentication middleware
    this.io.use(this.authMiddleware.bind(this));

    // Add event logging middleware
    this.io.use(this.loggingMiddleware.bind(this));

    // Setup event handlers
    this.setupEventHandlers();

    // Setup error handlers
    this.setupErrorHandlers();
  }

  async authMiddleware(socket, next) {
    try {
      const token = socket.handshake.auth.token;
      if (!token) {
        return next(new Error('Authentication token missing'));
      }
      
      const decoded = await verifyToken(token);
      socket.data.user = decoded;
      socket.join(`user:${decoded.id}`);
      next();
    } catch (error) {
      next(new Error('Authentication failed'));
    }
  }

  loggingMiddleware(socket, next) {
    const start = Date.now();
    
    socket.onAny((event, ...args) => {
      console.info('Socket Event', {
        event,
        userId: socket.data.user?.id,
        duration: Date.now() - start,
        args: JSON.stringify(args)
      });
    });
    
    next();
  }

  setupEventHandlers() {
    this.io.on('connection', (socket) => {
      console.log('Client connected:', socket.id);

      // Order subscription
      socket.on('order:subscribe', this.handleOrderSubscribe.bind(this, socket));

      // Cart updates
      socket.on('cart:update', this.handleCartUpdate.bind(this, socket));

      // Product stock watching
      socket.on('product:watch', this.handleProductWatch.bind(this, socket));

      // Disconnection
      socket.on('disconnect', this.handleDisconnect.bind(this, socket));
    });
  }

  setupErrorHandlers() {
    this.io.on('error', (error) => {
      console.error('Socket.IO error:', error);
    });
  }

  async handleOrderSubscribe(socket, orderId) {
    try {
      const userId = socket.data.user.id;
      const order = await Order.findOne({ _id: orderId, userId });
      if (order) {
        socket.join(`order:${orderId}`);
      }
    } catch (error) {
      console.error('Error in order subscription:', error);
      socket.emit('error', { message: 'Failed to subscribe to order updates' });
    }
  }

  async handleCartUpdate(socket, cartData) {
    try {
      const userId = socket.data.user.id;
      await Cart.updateOne({ userId }, cartData);
      socket.to(`user:${userId}`).emit('cart:updated', cartData);
    } catch (error) {
      console.error('Error in cart update:', error);
      socket.emit('error', { message: 'Failed to update cart' });
    }
  }

  async handleProductWatch(socket, productId) {
    try {
      socket.join(`product:${productId}`);
    } catch (error) {
      console.error('Error in product watch:', error);
      socket.emit('error', { message: 'Failed to watch product' });
    }
  }

  async handleDisconnect(socket, reason) {
    try {
      const userId = socket.data.user?.id;
      if (userId) {
        await this.updateUserStatus(userId, 'offline');
      }
      console.log(`Client disconnected (${reason})`);
    } catch (error) {
      console.error('Error in disconnect handler:', error);
    }
  }

  async updateUserStatus(userId, status) {
    try {
      await User.findByIdAndUpdate(userId, { status, lastSeen: new Date() });
    } catch (error) {
      console.error('Error updating user status:', error);
    }
  }

  // Utility methods for emitting events
  emitOrderUpdate(orderId, status) {
    this.io.to(`order:${orderId}`).emit('order:updated', orderId, status);
  }

  emitStockUpdate(productId, newStock) {
    this.io.to(`product:${productId}`).emit('product:stockUpdate', productId, newStock);
  }

  emitCartWarning(userId, productId, availableStock) {
    this.io.to(`user:${userId}`).emit('cart:stockWarning', { productId, availableStock });
  }
}

export default SocketService;