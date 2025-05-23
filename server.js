import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
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

// Import middleware
import { errorHandler } from './middleware/errorHandler.js';

// Initialize express app
const app = express();

// Configure CORS for frontend environments
app.use(cors({
  origin: [
    'http://localhost:8080',
    'https://shopify-dashboard-woad.vercel.app'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

// Set security headers with Helmet
app.use(helmet());

// Parse cookies
app.use(cookieParser());

// Enable CORS with specific options
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.FRONTEND_URL || 'https://shopify-dashboard-woad.vercel.app' 
    : ['http://localhost:8080', 'http://127.0.0.1:8080', 'http://localhost:5173', 'http://127.0.0.1:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

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
app.use('/api/auth', authRoutes);
app.use('/api/products', productsRouter);
app.use('/api/orders', orderRoutes);
app.use('/api/users', userRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/inventory', inventoryRoutes);
app.use('/api/cart', cartRoutes);
app.use('/api/categories', categoryRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/payments', paymentsRoutes);

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
  console.error('Error details:', {
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method,
    errorMessage: err.message,
    errorStack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    requestBody: req.body,
    requestQuery: req.query,
    userAgent: req.headers['user-agent'],
    userId: req.user?.uid
  });

  next(err);
});

// Error handling middleware
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
});

export default app;
dotenv.config();