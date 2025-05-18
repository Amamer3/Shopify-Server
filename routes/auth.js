import express from 'express';
import { body } from 'express-validator';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import fetch from 'node-fetch';
const router = express.Router();

// Import Firebase config
import { auth, db } from '../config/firebase.js';

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

    // Verify user exists first
    const userRecord = await auth.getUserByEmail(email);
    
    // Use Firebase Admin SDK to create a custom token
    // This will be used to authenticate with Firebase Auth REST API
    const customToken = await auth.createCustomToken(userRecord.uid);
    
    // Use Firebase Auth REST API to sign in with custom token
    const firebaseApiKey = process.env.FIREBASE_API_KEY;
    if (!firebaseApiKey) {
      throw new Error('Firebase API key is not configured');
    }
    
    // Exchange custom token for ID and refresh tokens
    const tokenExchangeUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=${firebaseApiKey}`;
    const tokenResponse = await fetch(tokenExchangeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: customToken, returnSecureToken: true })
    });
    
    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.json();
      console.error('Firebase token exchange error:', errorData);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Now verify the password with Firebase Auth REST API
    const signInUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${firebaseApiKey}`;
    const signInResponse = await fetch(signInUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, returnSecureToken: true })
    });
    
    if (!signInResponse.ok) {
      const errorData = await signInResponse.json();
      console.error('Firebase sign-in error:', errorData);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Get user data from Firestore
    const userDoc = await db.collection('users').doc(userRecord.uid).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'User not found in database' });
    }
    
    const userData = userDoc.data();
    
    // Generate JWT token
    const token = jwt.sign(
      { uid: userRecord.uid, email, role: userData.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(200).json({
      success: true,
      data: {
        user: {
          uid: userRecord.uid,
          firstName: userData.firstName,
          lastName: userData.lastName,
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
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], validateRequest, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const role = 'superadmin';

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
      createdAt: new Date().toISOString(),
      createdBy: req.user.uid // Track which superadmin created this superadmin
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
    console.error('Superadmin registration error:', error);
    next(error);
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