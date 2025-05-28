import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { createServer } from 'http';
import { Server } from 'socket.io';
import productsRouter from './routes/products.js';
import orderRoutes from './routes/orders.js';
import userRoutes from './routes/users.js';
import analyticsRoutes from './routes/analytics.js';
import inventoryRoutes from './routes/inventory.js';
import authRoutes from './routes/auth.js';
import cartRoutes from './routes/cart.js';
import categoryRoutes from './routes/categories.js';
import profileRoutes from './routes/profile.js';
import paymentsRoutes from './routes/payments.js';
import wishlistRoutes from './routes/wishlist.js';
// Import middleware
import { errorHandler } from './middleware/errorHandler.js';
import { protect, authorize } from './middleware/auth.js';
// import { createAdapter } from '@socket.io/redis-adapter';
// import { createClient } from 'redis';
// import { createRateLimiter } from '@socket.io/rate-limiter';
// Helper function for user status management
async function updateUserStatus(userId, status) {
  try {
    // Update user's online status in the database
    await User.findByIdAndUpdate(userId, { status, lastSeen: new Date() });
  } catch (error) {
    console.error('Error updating user status:', error);
  }
}
// Initialize express app and create HTTP server
const app = express();
const httpServer = createServer(app);
// Initialize Socket.IO service
// const socketService = new SocketService(httpServer); // Commented out, clarify initialization
const io = new Server(httpServer, {
  cors: {
    origin: process.env.NODE_ENV === 'production'
      ? [process.env.FRONTEND_URL, 'https://shopify-dashboard-woad.vercel.app', 'http://localhost:8080']
      : ['http://localhost:8080', 'http://127.0.0.1:8080', 'http://localhost:5173', 'http://127.0.0.1:5173'],
    credentials: true
  }
});
// Make io accessible to route handlers
app.set('io', io);
// Enable trust proxy
app.set('trust proxy', 1);
// Configure CORS for frontend environments
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? [process.env.FRONTEND_URL, 'https://shopify-dashboard-woad.vercel.app', 'http://localhost:8080']
    : ['http://localhost:8080', 'http://127.0.0.1:8080', 'http://localhost:5173', 'http://127.0.0.1:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
// Set security headers with Helmet
app.use(helmet());
// Parse cookies
app.use(cookieParser());
// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log({
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: `${duration}ms`,
      userAgent: req.headers['user-agent'],
      userId: req.user?.uid
    });
  });
  next();
});
// Parse JSON request body
app.use(express.json());
// Parse URL-encoded request body
app.use(express.urlencoded({ extended: true }));
// Apply rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes'
});
app.use('/api', limiter);
// Routes
app.use('/api/products', productsRouter);
app.use('/api/orders', orderRoutes);
app.use('/api/users', userRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/inventory', inventoryRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/cart', cartRoutes);
app.use('/api/categories', categoryRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/payments', paymentsRoutes);
app.use('/api/wishlist', wishlistRoutes);
// Health check endpoints
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    cpu: process.cpuUsage()
  });
});
// API status endpoint
app.get('/api/status', (req, res) => {
  res.status(200).json({
    status: 'operational',
    services: {
      auth: 'up',
      database: 'up',
      payment: 'up'
    },
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});
// Root route
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to Shopify Server API' });
});
// Error monitoring and logging
app.use((err, req, res, next) => {
  // Log error details
  const errorLog = {
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method,
    errorMessage: err.message,
    requestBody: req.body,
    requestQuery: req.query,
    userAgent: req.headers['user-agent'],
    userId: req.user?.uid
  };
  if (process.env.NODE_ENV === 'development') {
    errorLog.errorStack = err.stack;
  }
  console.error('Error details:', errorLog);
  next(err);
});
// Error handling middleware
app.use(errorHandler);
// Load environment variables
dotenv.config();
// Start server
const PORT = process.env.PORT || 10000;
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
  console.log('Socket.IO is ready for connections');
});
export default app;
// Example: Authenticated health check route using verifyToken
app.get('/api/health-auth', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.accessToken;
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    const decoded = await verifyToken(token);
    res.status(200).json({ status: 'ok', user: decoded });
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token', error: error.message });
  }
});