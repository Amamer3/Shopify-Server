const jwt = require('jsonwebtoken');
const { admin } = require('../config/firebase');

// Middleware to verify JWT token
exports.protect = async (req, res, next) => {
  let token;

  // Check if token exists in headers
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ message: 'Not authorized, no token provided' });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Get user from Firebase
    const user = await admin.auth().getUser(decoded.uid);
    
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    // Add user data to request object
    req.user = {
      uid: user.uid,
      email: user.email,
      role: decoded.role || 'staff' // Default to staff if role not specified
    };

    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(401).json({ message: 'Not authorized, token invalid' });
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