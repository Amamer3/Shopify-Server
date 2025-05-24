import express from 'express';
import { body } from 'express-validator';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import axios from 'axios';
import { signInWithEmailAndPassword } from 'firebase/auth';
import { AppError } from '../middleware/errorHandler.js';
const router = express.Router();

// Import Firebase config
import { auth, db, firebaseAdmin, firebaseClientAuth } from '../config/firebase.js';

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
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Password must contain at least one special character')
    .not().matches(/^(.{0,7}|[^0-9]*|[^A-Z]*|[^a-z]*|[a-zA-Z0-9]*)$/).withMessage('Password must meet all requirements')
], validateRequest, async (req, res, next) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    const role = 'user'; // Default role for public registration is 'user'

    // Check if user already exists
    try {
      const existingUser = await auth.getUserByEmail(email);
      if (existingUser) {
        return next(new AppError('Email already registered', 409));
      }
    } catch (error) {
      if (error.code !== 'auth/user-not-found') {
        console.error('Error checking existing user:', error);
        return next(new AppError('Error checking user existence', 500));
      }
    }

    // Create user in Firebase Authentication
    let userRecord;
    try {
      userRecord = await auth.createUser({
        email,
        password,
        displayName: `${firstName} ${lastName}`
      });
    } catch (error) {
      console.error('Error creating Firebase user:', error);
      return next(new AppError('Failed to create user account', 500));
    }

    // Store additional user data in Firestore
    try {
      await db.collection('users').doc(userRecord.uid).set({
        uid: userRecord.uid,
        firstName,
        lastName,
        email,
        role,
        createdAt: new Date().toISOString()
      });
    } catch (error) {
      console.error('Error storing user data in Firestore:', error);
      // Attempt to delete the Firebase Auth user if Firestore save fails
      try {
        await auth.deleteUser(userRecord.uid);
      } catch (deleteError) {
        console.error('Error cleaning up Firebase Auth user after Firestore failure:', deleteError);
      }
      return next(new AppError('Failed to save user data', 500));
    }

    // Generate JWT token
    let token;
    try {
      token = jwt.sign(
        { uid: userRecord.uid, email, role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );
    } catch (error) {
      console.error('Error generating JWT token:', error);
      return next(new AppError('Failed to generate authentication token', 500));
    }

    // Send password reset email using secure email service
    try {
      const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
      const emailResponse = await axios.post(process.env.EMAIL_SERVICE_URL, {
        to: email,
        subject: 'Password Reset',
        text: `Click the link to reset your password: ${resetLink}`,
        html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`
      }, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.EMAIL_SERVICE_KEY}`
        }
      });

      if (emailResponse.status !== 200) {
        console.error('Email service error:', emailResponse.data);
        // Don't throw error here, just log it as the user account is already created
        console.warn('Failed to send password reset email, but user account was created successfully');
      }
    } catch (error) {
      console.error('Error sending password reset email:', error);
      // Don't throw error here, just log it as the user account is already created
      console.warn('Failed to send password reset email, but user account was created successfully');
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
    next(new AppError('Registration failed', 500));
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
 * @route   POST /api/auth/admin/login
 * @desc    Login for admin, superadmin, and manager roles
 * @access  Public
 */
router.post('/admin/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], validateRequest, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Sign in with Firebase Authentication
    const userCredential = await auth.signInWithEmailAndPassword(email, password);
    const user = userCredential.user;

    // Get user data from Firestore
    const userData = await db.collection('users').doc(user.uid).get();
    const userRole = userData.data().role;

    // Check if user has admin privileges
    if (!['admin', 'superadmin', 'manager'].includes(userRole)) {
      throw new AppError('Unauthorized access. Admin privileges required.', 403);
    }

    // Generate JWT token with role
    const token = jwt.sign(
      { uid: user.uid, email: user.email, role: userRole },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(200).json({
      success: true,
      data: {
        user: {
          uid: user.uid,
          email: user.email,
          role: userRole
        },
        token
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/auth/register-admin
 * @desc    Register a new admin (superadmin access only)
 * @access  Superadmin
 */
router.post('/register-admin', protect, authorize('superadmin'), [
  body('firstName').notEmpty().withMessage('First name is required'),
  body('lastName').notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
], validateRequest, async (req, res, next) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    const role = 'admin';

    // Create admin user in Firebase Authentication
    const userRecord = await auth.createUser({
      email,
      password,
      displayName: `${firstName} ${lastName}`
    });

    // Set custom claims for admin role
    await firebaseAdmin.auth().setCustomUserClaims(userRecord.uid, { role });

    // Store additional user data in Firestore
    await db.collection('users').doc(userRecord.uid).set({
      uid: userRecord.uid,
      firstName,
      lastName,
      email,
      role,
      createdAt: new Date().toISOString()
    });

    res.status(201).json({
      success: true,
      data: {
        user: {
          uid: userRecord.uid,
          firstName,
          lastName,
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
 * @desc    Register a new superadmin (superadmin access only)
 * @access  Superadmin
 */
router.post('/register-superadmin', protect, authorize('superadmin'), [
  body('firstName').notEmpty().withMessage('First name is required'),
  body('lastName').notEmpty().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
], validateRequest, async (req, res, next) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    const role = 'superadmin';

    // Create superadmin user in Firebase Authentication
    const userRecord = await auth.createUser({
      email,
      password,
      displayName: `${firstName} ${lastName}`
    });

    // Set custom claims for superadmin role
    await firebaseAdmin.auth().setCustomUserClaims(userRecord.uid, { role });

    // Store additional user data in Firestore
    await db.collection('users').doc(userRecord.uid).set({
      uid: userRecord.uid,
      firstName,
      lastName,
      email,
      role,
      createdAt: new Date().toISOString()
    });

    res.status(201).json({
      success: true,
      data: {
        user: {
          uid: userRecord.uid,
          firstName,
          lastName,
          email,
          role
        }
      }
    });
  } catch (error) {
    console.error('Superadmin registration error:', error);
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

    // Generate password reset link
    const resetLink = await firebaseAdmin.auth().generatePasswordResetLink(email);

    // Send password reset email
    await axios.post(process.env.EMAIL_SERVICE_URL, {
      to: email,
      subject: 'Password Reset Request',
      text: `Click the link to reset your password: ${resetLink}`,
      html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.EMAIL_SERVICE_KEY}`
      }
    });

    res.status(200).json({
      success: true,
      message: 'Password reset email sent'
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/auth/reset-password/:token
 * @desc    Reset user password with token
 * @access  Public
 */
router.post('/reset-password/:token', [
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
], validateRequest, async (req, res, next) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    // Verify reset token and get user
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await auth.getUser(decoded.uid);

    if (!user) {
      return next(new AppError('Invalid token', 401));
    }

    // Update user password in Firebase Authentication
    await auth.updateUser(user.uid, { password });

    // Update user password in Firestore database
    await db.collection('users').doc(user.uid).update({ password });

    res.status(200).json({
      success: true,
      message: 'Password has been reset'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/auth/verify-email
 * @desc    Verify user email address
 * @access  Public
 */
router.post('/verify-email', [
  body('email').isEmail().withMessage('Please provide a valid email')
], validateRequest, async (req, res, next) => {
  try {
    const { email } = req.body;

    // Generate email verification link
    const verifyLink = await firebaseAdmin.auth().generateEmailVerificationLink(email);

    // Send verification email
    await axios.post(process.env.EMAIL_SERVICE_URL, {
      to: email,
      subject: 'Email Verification',
      text: `Click the link to verify your email: ${verifyLink}`,
      html: `<p>Click <a href="${verifyLink}">here</a> to verify your email.</p>`
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.EMAIL_SERVICE_KEY}`
      }
    });

    res.status(200).json({
      success: true,
      message: 'Verification email sent'
    });
  } catch (error) {
    console.error('Verify email error:', error);
    next(error);
  }
});

// Export router
export default router;

/**
 * @route   POST /api/auth/login
 * @desc    Login for regular users
 * @access  Public
 */
router.post('/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], validateRequest, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Sign in with Firebase Client Auth
    let userCredential;
    try {
      userCredential = await signInWithEmailAndPassword(firebaseClientAuth, email, password);
    } catch (authError) {
      console.error('Firebase Authentication error:', authError);
      return next(new AppError(authError.message || 'Invalid email or password', 401));
    }

    const user = userCredential.user;

    // Get user data from Firestore
    let userDoc;
    try {
      userDoc = await db.collection('users').doc(user.uid).get();
      if (!userDoc.exists) {
        throw new Error('User data not found');
      }
    } catch (dbError) {
      console.error('Firestore error:', dbError);
      return next(new AppError('Error retrieving user data', 500));
    }

    const userData = userDoc.data();
    const userRole = userData.role || 'user';

    // Generate JWT token with role
    let token;
    try {
      token = jwt.sign(
        { uid: user.uid, email: user.email, role: userRole },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );
    } catch (tokenError) {
      console.error('JWT generation error:', tokenError);
      return next(new AppError('Error generating authentication token', 500));
    }

    res.status(200).json({
      success: true,
      data: {
        user: {
          uid: user.uid,
          email: user.email,
          firstName: userData.firstName,
          lastName: userData.lastName,
          role: userRole
        },
        token
      }
    });
  } catch (error) {
    console.error('Unexpected login error:', error);
    next(new AppError('Authentication failed', 500));
  }
});
