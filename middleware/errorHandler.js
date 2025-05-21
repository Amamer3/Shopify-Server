/**
 * Error handling middleware
 */
import { validationResult } from 'express-validator';

// Validation error handler
export const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Global error handler middleware
export const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  
  // Log error with request details
  console.error(`[ERROR] ${new Date().toISOString()}`);
  console.error(`Path: ${req.method} ${req.path}`);
  console.error(`User: ${req.user?.uid || 'Not authenticated'}`);
  console.error(`Message: ${err.message}`);
  console.error(`Stack: ${err.stack}`);
  
  if (err.code) {
    console.error(`Error Code: ${err.code}`);
  }

  // Send response
  res.status(statusCode).json({
    success: false,
    error: {
      message: err.message || 'Server Error',
      code: err.code,
      status: statusCode,
      path: req.path,
      timestamp: new Date().toISOString(),
      ...(process.env.NODE_ENV === 'development' && { 
        stack: err.stack,
        details: err.details || err.errors
      })
    }
  });
};

// Not found error handler
export const notFound = (req, res, next) => {
  const error = new Error(`Not Found - ${req.originalUrl}`);
  error.statusCode = 404;
  next(error);
};

// Custom error class
export class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
};