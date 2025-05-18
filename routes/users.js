import express from 'express';
import { body } from 'express-validator';
const router = express.Router();

// Import Firebase config
import { db, auth } from '../config/firebase.js';

// Import middleware
import { validateRequest } from '../middleware/errorHandler.js';
import { protect, authorize } from '../middleware/auth.js';

/**
 * @route   GET /api/users
 * @desc    Get all users
 * @access  Private (Admin)
 */
router.get('/', protect, authorize('admin'), async (req, res, next) => {
  try {
    const usersSnapshot = await db.collection('users').get();
    const users = [];
    
    usersSnapshot.forEach(doc => {
      users.push({
        id: doc.id,
        ...doc.data()
      });
    });

    res.status(200).json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (error) {
    console.error('Get users error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/users/:id
 * @desc    Get single user
 * @access  Private (Admin, or own profile)
 */
router.get('/:id', protect, async (req, res, next) => {
  try {
    // Check if user is authorized to view this profile
    if (req.params.id !== req.user.uid && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to view this profile' });
    }

    const userDoc = await db.collection('users').doc(req.params.id).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({
      success: true,
      data: {
        id: userDoc.id,
        ...userDoc.data()
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    next(error);
  }
});

/**
 * @route   PUT /api/users/:id
 * @desc    Update user profile
 * @access  Private (Admin, or own profile)
 */
router.put('/:id', [
  protect,
  body('name').optional().notEmpty().withMessage('Name cannot be empty'),
  body('email').optional().isEmail().withMessage('Please provide a valid email'),
  body('role').optional().isIn(['admin', 'manager', 'staff']).withMessage('Invalid role')
], validateRequest, async (req, res, next) => {
  try {
    // Check if user is authorized to update this profile
    if (req.params.id !== req.user.uid && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized to update this profile' });
    }

    // Check if user exists
    const userDoc = await db.collection('users').doc(req.params.id).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'User not found' });
    }

    const updateData = { ...req.body };
    
    // Only admin can update roles
    if (updateData.role && req.user.role !== 'admin') {
      delete updateData.role;
    }

    // Update user in Firestore
    await db.collection('users').doc(req.params.id).update({
      ...updateData,
      updatedAt: new Date().toISOString()
    });

    // If email is being updated, update in Firebase Auth as well
    if (updateData.email) {
      await auth.updateUser(req.params.id, {
        email: updateData.email
      });
    }

    // Get updated user
    const updatedUserDoc = await db.collection('users').doc(req.params.id).get();

    res.status(200).json({
      success: true,
      data: {
        id: updatedUserDoc.id,
        ...updatedUserDoc.data()
      }
    });
  } catch (error) {
    console.error('Update user error:', error);
    next(error);
  }
});

/**
 * @route   DELETE /api/users/:id
 * @desc    Delete a user
 * @access  Private (Admin)
 */
router.delete('/:id', protect, authorize('admin'), async (req, res, next) => {
  try {
    // Check if user exists
    const userDoc = await db.collection('users').doc(req.params.id).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Delete user from Firestore
    await db.collection('users').doc(req.params.id).delete();
    
    // Delete user from Firebase Auth
    await auth.deleteUser(req.params.id);

    res.status(200).json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Delete user error:', error);
    next(error);
  }
});

export default router;