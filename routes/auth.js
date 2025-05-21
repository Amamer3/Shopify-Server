import express from 'express';
import { body } from 'express-validator';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import axios from 'axios';
import { AppError } from '../middleware/errorHandler.js';
const router = express.Router();

// Import Firebase config
import { auth, db, firebaseAdmin } from '../config/firebase.js';

// Import middleware
import { validateRequest } from '../middleware/errorHandler.js';
import { protect, authorize } from '../middleware/auth.js';

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', [
  body('firstName').notEmpty().withMessage('First name is required'),
  body('lastName').notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Password must contain at least one special character')
    .not().matches(/^(.{0,7}|[^0-9]*|[^A-Z]*|[^a-z]*|[a-zA-Z0-9]*)$/).withMessage('Password must meet all requirements')
], validateRequest, async (req, res, next) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    const role = 'user'; // Default role for public registration is 'user'

    // Create user in Firebase Authentication
    const userRecord = await auth.createUser({
      email,
      password,
      displayName: `${firstName} ${lastName}`
    });

    // Store additional user data in Firestore
    await db.collection('users').doc(userRecord.uid).set({
      uid: userRecord.uid,
      firstName,
      lastName,
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

    // Send password reset email using secure email service
    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    const emailResponse = await fetch(process.env.EMAIL_SERVICE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.EMAIL_SERVICE_KEY}`
      },
      body: JSON.stringify({
        to: email,
        subject: 'Password Reset',
        text: `Click the link to reset your password: ${resetLink}`,
        html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`
      })
    });

    if (!emailResponse.ok) {
      throw new Error('Failed to send password reset email');
    }

    res.status(201).json({
      success: true,
      data: {
        user: {
          uid: userRecord.uid,
          firstName,
          lastName,
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
 * @route   GET /api/auth/status
 * @desc    Check if user is authenticated without full validation
 * @access  Public
 */
router.get('/status', (req, res) => {
  // Check if access token exists in headers or cookies
  let hasToken = false;
  
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    hasToken = true;
  } else if (req.cookies?.accessToken) {
    hasToken = true;
  }
  
  // Check if refresh token exists
  const hasRefreshToken = !!req.cookies?.refreshToken;
  
  res.status(200).json({
    isAuthenticated: hasToken,
    hasRefreshToken,
    authMethod: hasToken ? 'token' : (hasRefreshToken ? 'refresh_token' : 'none')
  });
});

/**
 * @route   GET /api/auth/validate
 * @desc    Validate a token and return user info
 * @access  Protected
 */
router.get('/validate', protect, async (req, res, next) => {
  try {
    // Token is already validated by the protect middleware
    // Get user from Firebase
    const user = await auth.getUser(req.user.uid);
    
    // Get additional user data from Firestore
    const userDoc = await db.collection('users').doc(user.uid).get();
    const userData = userDoc.data() || {};
    
    // Return user info with extended profile data
    res.status(200).json({
      valid: true,
      user: {
        uid: user.uid,
        email: user.email,
        firstName: userData.firstName,
        lastName: userData.lastName,
        role: req.user.role || userData.role || 'user',
        createdAt: userData.createdAt,
        lastLogin: user.metadata?.lastSignInTime
      },
      tokenExpiry: req.tokenExpiry // This will be set if we add it to the protect middleware
    });
  } catch (error) {
    console.error('Token validation error:', error);
    
    if (error.code === 'auth/user-not-found') {
      return next(new AppError('User not found', 404));
    }
    
    next(new AppError('Invalid token', 401));
  }
});

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token using refresh token
 * @access  Public
 */
router.post('/refresh', async (req, res, next) => {
  try {
    // Get refresh token from cookie or request body
    const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;
    const { storeTokenInCookie = false } = req.body;
    
    if (!refreshToken) {
      return next(new AppError('Refresh token is required', 400));
    }
    
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
    
    // Get user from Firebase
    const user = await auth.getUser(decoded.uid);
    
    if (!user) {
      return next(new AppError('User not found', 404));
    }
    
    // Get user role from Firestore
    const userDoc = await db.collection('users').doc(user.uid).get();
    const userData = userDoc.data();
    const role = userData?.role || 'user';
    
    // Generate new access token
    const accessToken = jwt.sign(
      { uid: user.uid, email: user.email, role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );
    
    // Generate new refresh token with rotation for security
    const newRefreshToken = jwt.sign(
      { uid: user.uid },
      process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );
    
    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // 'none' for cross-site requests in production
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    // If client requests to store access token in cookie
    if (storeTokenInCookie) {
      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        maxAge: 60 * 60 * 1000, // 1 hour
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
      });
    }
    
    // Log token refresh for audit purposes
    console.log(`Token refreshed for user ${user.uid} at ${new Date().toISOString()}`);
    
    // Return the new access token
    res.status(200).json({
      success: true,
      accessToken,
      expiresIn: process.env.JWT_EXPIRES_IN || '1h'
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    
    // Handle specific JWT errors
    if (error.name === 'JsonWebTokenError') {
      return next(new AppError('Invalid refresh token format', 401));
    } else if (error.name === 'TokenExpiredError') {
      // Clear the expired refresh token cookie
      res.cookie('refreshToken', '', {
        httpOnly: true,
        expires: new Date(0),
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
      });
      
      return next(new AppError('Refresh token has expired, please login again', 401));
    }
    
    // Handle other errors
    next(new AppError('Failed to refresh token', 500));
  }
});

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user by clearing refresh token cookie
 * @access  Public
 */
router.post('/logout', (req, res) => {
  // Clear the refresh token cookie
  res.cookie('refreshToken', '', {
    httpOnly: true,
    expires: new Date(0), // Set expiration to epoch time (effectively deleting it)
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  });
  
  // Clear the access token cookie if it exists
  if (req.cookies?.accessToken) {
    res.cookie('accessToken', '', {
      httpOnly: true,
      expires: new Date(0),
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
    });
  }
  
  res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
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
    const { email, password, storeTokenInCookie = false } = req.body;

    // Verify user exists first
    const userRecord = await auth.getUserByEmail(email);
    
    // Sign in with email and password using Firebase Auth REST API
    const firebaseApiKey = process.env.FIREBASE_API_KEY;
    if (!firebaseApiKey) {
      throw new Error('Firebase API key is not configured');
    }
    
    const signInUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${firebaseApiKey}`;
    try {
      await axios.post(signInUrl, {
        email,
        password,
        returnSecureToken: true
      });
    } catch (error) {
      console.error('Firebase authentication error:', error.response?.data || error.message);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Get user data from Firestore
    const userDoc = await db.collection('users').doc(userRecord.uid).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'User not found in database' });
    }
    
    const userData = userDoc.data();
    
    // Update last login time
    await db.collection('users').doc(userRecord.uid).update({
      lastLogin: new Date().toISOString()
    });
    
    // Verify JWT secret is configured
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET is not configured');
      return next(new AppError('Server configuration error', 500));
    }
    
    // Generate access token
    let accessToken;
    try {
      accessToken = jwt.sign(
        { uid: userRecord.uid, email, role: userData.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
      );
      
      if (!accessToken) {
        throw new Error('Failed to generate access token');
      }
    } catch (error) {
      console.error('Token generation error:', error);
      return next(new AppError('Authentication failed: Unable to generate token', 500));
    }
    
    // Generate refresh token
    let refreshToken;
    try {
      refreshToken = jwt.sign(
        { uid: userRecord.uid },
        process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
      );
      
      if (!refreshToken) {
        throw new Error('Failed to generate refresh token');
      }
    } catch (error) {
      console.error('Refresh token generation error:', error);
      return next(new AppError('Authentication failed: Unable to generate refresh token', 500));
    }
    
    // Set refresh token as HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    // If client requests to store access token in cookie
    if (storeTokenInCookie) {
      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        maxAge: 60 * 60 * 1000, // 1 hour
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        user: {
          uid: userRecord.uid,
          firstName: userData.firstName,
          lastName: userData.lastName,
          email,
          role: userData.role,
          lastLogin: new Date().toISOString()
        },
        accessToken,
        expiresIn: 3600 // 1 hour in seconds
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    
    if (error.code === 'auth/user-not-found' || error.code === 'auth/wrong-password') {
      return next(new AppError('Invalid email or password', 401));
    }
    
    if (error.code === 'auth/too-many-requests') {
      return next(new AppError('Too many failed login attempts. Please try again later or reset your password.', 429));
    }
    
    next(error);
  }
});

/**
 * @route   POST /api/auth/register-admin
 * @desc    Register a new admin (superadmin only)
 * @access  Private (superadmin)
 */
router.post('/register-admin', protect, authorize('superadmin'), [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], validateRequest, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const role = 'admin';

    // Create admin user in Firebase Authentication
    const userRecord = await auth.createUser({
      email,
      password,
      displayName: email.split('@')[0] // Use part of email as display name
    });

    // Store admin data in Firestore
    await db.collection('users').doc(userRecord.uid).set({
      uid: userRecord.uid,
      email,
      role,
      createdAt: new Date().toISOString(),
      createdBy: req.user.uid // Track which superadmin created this admin
    });

    res.status(201).json({
      success: true,
      data: {
        user: {
          uid: userRecord.uid,
          email,
          role
        }
      }
    });
  } catch (error) {
    console.error('Admin registration error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/auth/register-superadmin
 * @desc    Register a new superadmin (first-time setup or existing superadmin only)
 * @access  Private (superadmin) or special setup process
 */
router.post('/register-superadmin', protect, authorize('superadmin'), [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  body('permissions').optional().isArray().withMessage('Permissions must be an array')
], validateRequest, async (req, res, next) => {
  try {
    const { email, password, permissions = [] } = req.body;
    const role = 'superadmin';

    // Check if email already exists
    try {
      const existingUser = await auth.getUserByEmail(email);
      if (existingUser) {
        return next(new AppError('Email already registered', 400));
      }
    } catch (error) {
      if (error.code !== 'auth/user-not-found') {
        throw error;
      }
    }

    // Create superadmin user in Firebase Authentication
    const userRecord = await auth.createUser({
      email,
      password,
      displayName: email.split('@')[0] // Use part of email as display name
    });

    // Store superadmin data in Firestore
    await db.collection('users').doc(userRecord.uid).set({
      uid: userRecord.uid,
      email,
      role,
      permissions,
      createdAt: new Date().toISOString(),
      createdBy: req.user.uid // Track which superadmin created this superadmin
    });

    res.status(201).json({
      success: true,
      data: {
        user: {
          uid: userRecord.uid,
          email,
          role,
          permissions
        }
      }
    });
  } catch (error) {
    console.error('Superadmin registration error:', error);
    
    if (error.code === 'auth/email-already-exists') {
      return next(new AppError('Email already registered', 400));
    }
    
    if (error.code === 'auth/invalid-password') {
      return next(new AppError('Invalid password format', 400));
    }
    
    next(new AppError('Failed to create superadmin user', 500));
  }
});

/**
 * @route   POST /api/auth/verify-email
 * @desc    Verify user email
 * @access  Private
 */
router.post('/verify-email', protect, async (req, res, next) => {
  try {
    // In a real implementation, you would generate a verification link
    // and send it to the user's email
    
    // For now, we'll just mark the user as verified
    await db.collection('users').doc(req.user.uid).update({
      emailVerified: true,
      updatedAt: new Date().toISOString()
    });
    
    res.status(200).json({
      success: true,
      message: 'Email verified successfully'
    });
  } catch (error) {
    console.error('Email verification error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Send password reset email
 * @access  Public
 */
router.post('/forgot-password', [
  body('email').isEmail().withMessage('Please provide a valid email')
], validateRequest, async (req, res, next) => {
  try {
    const { email } = req.body;

    // Check if user exists
    const userRecord = await auth.getUserByEmail(email);
    
    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpire = Date.now() + 3600000; // 1 hour
    
    // Store reset token in Firestore
    await db.collection('passwordResets').doc(userRecord.uid).set({
      resetToken,
      resetTokenExpire,
      email
    });
    
    // In a production environment, you would send an email with the reset link
    // For now, we'll just return the token in the response
    res.status(200).json({
      success: true,
      message: 'Password reset email sent',
      data: {
        resetToken,
        // In production, remove this and send via email instead
        resetUrl: `${process.env.FRONTEND_URL}/reset-password/${resetToken}`
      }
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    // Don't reveal if the email exists or not for security
    res.status(200).json({
      success: true,
      message: 'If that email exists, a password reset link has been sent'
    });
  }
});

/**
 * @route   POST /api/auth/reset-password/:token
 * @desc    Reset password using token
 * @access  Public
 */
router.post('/reset-password/:token', [
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], validateRequest, async (req, res, next) => {
  try {
    const { token } = req.params;
    const { password } = req.body;
    
    // Find reset token in database
    const resetDocsSnapshot = await db.collection('passwordResets')
      .where('resetToken', '==', token)
      .where('resetTokenExpire', '>', Date.now())
      .get();
    
    if (resetDocsSnapshot.empty) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }
    
    // Get the first matching document
    const resetDoc = resetDocsSnapshot.docs[0];
    const resetData = resetDoc.data();
    const userId = resetDoc.id;
    
    // Update user password
    await auth.updateUser(userId, {
      password
    });
    
    // Delete the reset token
    await db.collection('passwordResets').doc(userId).delete();
    
    res.status(200).json({
      success: true,
      message: 'Password has been reset successfully'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    next(error);
  }
});

// Export router
export default router;