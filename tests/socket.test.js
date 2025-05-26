import { createServer } from 'http';
import { io as Client } from 'socket.io-client';
import { Server } from 'socket.io';
import SocketService from '../services/socket.js';
import { jest } from '@jest/globals';

describe('Socket.IO Service', () => {
  let httpServer;
  let socketService;
  let clientSocket;
  let port;

  beforeAll(() => {
    // Mock environment variables
    process.env.NODE_ENV = 'test';
    process.env.REDIS_URL = 'redis://localhost:6379';
  });

  beforeEach((done) => {
    // Create HTTP server
    httpServer = createServer();
    socketService = new SocketService(httpServer);
    
    // Start server and get port
    httpServer.listen(() => {
      port = httpServer.address().port;
      
      // Create client socket
      clientSocket = Client(`http://localhost:${port}`, {
        auth: {
          token: 'valid-test-token'
        }
      });
      
      clientSocket.on('connect', done);
    });
  });

  afterEach(() => {
    // Cleanup
    clientSocket.close();
    httpServer.close();
  });

  // Test authentication
  describe('Authentication', () => {
    test('should connect with valid token', (done) => {
      clientSocket.on('connect', () => {
        expect(clientSocket.connected).toBe(true);
        done();
      });
    });

    test('should reject connection without token', (done) => {
      const unauthSocket = Client(`http://localhost:${port}`, {
        auth: {}
      });

      unauthSocket.on('connect_error', (err) => {
        expect(err.message).toBe('Authentication token missing');
        unauthSocket.close();
        done();
      });
    });
  });

  // Test order events
  describe('Order Events', () => {
    test('should subscribe to order updates', (done) => {
      const orderId = 'test-order-123';
      const userId = 'test-user-123';

      // Mock Order.findOne
      global.Order = {
        findOne: jest.fn().mockResolvedValue({ _id: orderId, userId })
      };

      clientSocket.emit('order:subscribe', orderId);

      setTimeout(() => {
        expect(global.Order.findOne).toHaveBeenCalledWith({
          _id: orderId,
          userId: expect.any(String)
        });
        done();
      }, 100);
    });

    test('should receive order updates', (done) => {
      const orderId = 'test-order-123';
      const status = 'processing';

      clientSocket.on('order:updated', (data) => {
        expect(data).toEqual({
          orderId,
          status,
          timestamp: expect.any(String)
        });
        done();
      });

      // Simulate order update
      socketService.emitOrderUpdate(orderId, status);
    });
  });

  // Test cart events
  describe('Cart Events', () => {
    test('should handle cart updates', (done) => {
      const cartData = {
        userId: 'test-user-123',
        items: [{ productId: 'test-prod-1', quantity: 2 }]
      };

      // Mock Cart.updateOne
      global.Cart = {
        updateOne: jest.fn().mockResolvedValue(true)
      };

      clientSocket.emit('cart:update', cartData);

      setTimeout(() => {
        expect(global.Cart.updateOne).toHaveBeenCalledWith(
          { userId: expect.any(String) },
          cartData
        );
        done();
      }, 100);
    });

    test('should receive cart stock warnings', (done) => {
      const warningData = {
        productId: 'test-prod-1',
        availableStock: 2
      };

      clientSocket.on('cart:stockWarning', (data) => {
        expect(data).toEqual(warningData);
        done();
      });

      // Simulate stock warning
      socketService.emitCartWarning(
        'test-user-123',
        warningData.productId,
        warningData.availableStock
      );
    });
  });

  // Test product events
  describe('Product Events', () => {
    test('should watch product stock', (done) => {
      const productId = 'test-prod-1';
      const newStock = 5;

      clientSocket.emit('product:watch', productId);

      clientSocket.on('product:stockUpdate', (data) => {
        expect(data).toEqual({
          productId,
          newStock
        });
        done();
      });

      // Simulate stock update
      setTimeout(() => {
        socketService.emitStockUpdate(productId, newStock);
      }, 100);
    });
  });

  // Test disconnection
  describe('Disconnection', () => {
    test('should handle user disconnection', (done) => {
      // Mock User.findByIdAndUpdate
      global.User = {
        findByIdAndUpdate: jest.fn().mockResolvedValue(true)
      };

      clientSocket.on('connect', () => {
        clientSocket.close();
      });

      setTimeout(() => {
        expect(global.User.findByIdAndUpdate).toHaveBeenCalledWith(
          expect.any(String),
          {
            status: 'offline',
            lastSeen: expect.any(Date)
          }
        );
        done();
      }, 100);
    });
  });

  // Test error handling
  describe('Error Handling', () => {
    test('should handle cart update errors', (done) => {
      // Mock Cart.updateOne to throw error
      global.Cart = {
        updateOne: jest.fn().mockRejectedValue(new Error('Database error'))
      };

      clientSocket.on('error', (error) => {
        expect(error.message).toBe('Failed to update cart');
        done();
      });

      clientSocket.emit('cart:update', {
        userId: 'test-user-123',
        items: []
      });
    });
  });
});