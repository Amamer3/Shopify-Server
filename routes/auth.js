const express = require('express');
const { body } = require('express-validator');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Import Firebase config
const { auth, db } = require('../config/firebase');

// Import middleware
const { validateRequest } = require('../middleware/errorHandler');
const { protect, authorize } = require('../middleware/auth');

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  body('name').notEmpty().withMessage('Name is required'),
  body('role').optional().isIn(['admin', 'manager', 'staff']).withMessage('Invalid role')
], validateRequest, async (req, res, next) => {
  try {
    const { email, password, name, role = 'staff' } = req.body;

    // Create user in Firebase Authentication
    const userRecord = await auth.createUser({
      email,
      password,
      displayName: name
    });

    // Store additional user data in Firestore
    await db.collection('users').doc(userRecord.uid).set({
      uid: userRecord.uid,
      name,
      email,
      role,
      createdAt: new Date().toISOString()
    });

    // Generate JWT token
    const token = jwt.sign(
      { uid: userRecord.uid, email, role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(201).json({
      success: true,
      data: {
        user: {
          uid: userRecord.uid,
          name,
          email,
          role
        },
        token
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/auth/login
 * @desc    Login user and return JWT token
 * @access  Public
 */
router.post('/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], validateRequest, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Sign in with Firebase Authentication
    const signInResult = await auth.getUserByEmail(email);
    
    // Get user data from Firestore
    const userDoc = await db.collection('users').doc(signInResult.uid).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const userData = userDoc.data();

    // Generate JWT token
    const token = jwt.sign(
      { uid: signInResult.uid, email, role: userData.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(200).json({
      success: true,
      data: {
        user: {
          uid: signInResult.uid,
          name: userData.name,
          email: userData.email,
          role: userData.role
        },
        token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/me', protect, async (req, res, next) => {
  try {
    // Get user data from Firestore
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const userData = userDoc.data();

    res.status(200).json({
      success: true,
      data: {
        user: userData
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user (client-side only)
 * @access  Private
 */
router.post('/logout', protect, (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
});

module.exports = router;