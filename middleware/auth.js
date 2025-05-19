import { auth, firebaseAdmin } from '../config/firebase.js';
import jwt from 'jsonwebtoken';
import { AppError } from './errorHandler.js';

// Middleware to verify JWT token
export const protect = async (req, res, next) => {
  let token;

  // Check if token exists in headers or cookies
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies?.accessToken) {
    token = req.cookies.accessToken;
  }

  if (!token) {
    return next(new AppError('Not authorized, no token provided', 401));
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Calculate token expiry time
    const expiryTime = new Date(decoded.exp * 1000);
    const now = new Date();
    const timeRemaining = Math.floor((expiryTime - now) / 1000); // seconds remaining

    // Get user from Firebase
    const user = await firebaseAdmin.auth().getUser(decoded.uid);
    
    if (!user) {
      return next(new AppError('User not found', 401));
    }

    // Add user data and token info to request object
    req.user = {
      uid: user.uid,
      email: user.email,
      role: decoded.role || 'user' // Default to user if role not specified
    };
    
    // Add token expiry information
    req.tokenExpiry = {
      expiresAt: expiryTime.toISOString(),
      expiresIn: timeRemaining,
      issuedAt: new Date(decoded.iat * 1000).toISOString()
    };

    // If token is about to expire (less than 5 minutes), set a flag
    if (timeRemaining < 300) {
      req.tokenNearExpiry = true;
    }

    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    // Handle token expiration specifically
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: 'Token expired', 
        code: 'TOKEN_EXPIRED',
        needsRefresh: true
      });
    }
    
    // Handle other JWT errors
    if (error.name === 'JsonWebTokenError') {
      return next(new AppError('Invalid token format', 401));
    }
    
    return next(new AppError('Not authorized, token invalid', 401));
  }
};

// Middleware to authorize based on user role
export const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'User not authenticated' });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        message: `User role ${req.user.role} is not authorized to access this resource`
      });
    }
    
    next();
  };
};