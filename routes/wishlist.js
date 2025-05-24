import express from 'express';
import { body } from 'express-validator';
import { db } from '../config/firebase.js';
import { protect } from '../middleware/auth.js';
import { validateRequest } from '../middleware/errorHandler.js';
import { AppError } from '../middleware/errorHandler.js';

const router = express.Router();

/**
 * @route   POST /api/wishlist
 * @desc    Add a product to user's wishlist
 * @access  Private
 */
router.post('/', protect, [
  body('productId').notEmpty().withMessage('Product ID is required')
], validateRequest, async (req, res, next) => {
  try {
    const { productId } = req.body;
    const userId = req.user.uid;

    // Check if product exists
    const productDoc = await db.collection('products').doc(productId).get();
    if (!productDoc.exists) {
      return next(new AppError('Product not found', 404));
    }

    // Check if product is already in wishlist
    const wishlistRef = db.collection('wishlists').doc(userId);
    const wishlistDoc = await wishlistRef.get();

    if (wishlistDoc.exists) {
      const wishlist = wishlistDoc.data();
      if (wishlist.products.includes(productId)) {
        return next(new AppError('Product already in wishlist', 400));
      }

      // Add product to existing wishlist
      await wishlistRef.update({
        products: [...wishlist.products, productId],
        updatedAt: new Date().toISOString()
      });
    } else {
      // Create new wishlist
      await wishlistRef.set({
        userId,
        products: [productId],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });
    }

    res.status(201).json({
      success: true,
      message: 'Product added to wishlist'
    });
  } catch (error) {
    console.error('Add to wishlist error:', error);
    next(new AppError('Failed to add product to wishlist', 500));
  }
});

/**
 * @route   GET /api/wishlist
 * @desc    Get user's wishlist
 * @access  Private
 */
router.get('/', protect, async (req, res, next) => {
  try {
    const userId = req.user.uid;

    // Get wishlist
    const wishlistDoc = await db.collection('wishlists').doc(userId).get();
    if (!wishlistDoc.exists) {
      return res.status(200).json({
        success: true,
        data: {
          products: []
        }
      });
    }

    // Get product details
    const wishlist = wishlistDoc.data();
    const productRefs = wishlist.products.map(productId => 
      db.collection('products').doc(productId).get()
    );
    const productDocs = await Promise.all(productRefs);

    const products = productDocs
      .filter(doc => doc.exists)
      .map(doc => ({
        id: doc.id,
        ...doc.data()
      }));

    res.status(200).json({
      success: true,
      data: {
        products
      }
    });
  } catch (error) {
    console.error('Get wishlist error:', error);
    next(new AppError('Failed to get wishlist', 500));
  }
});

/**
 * @route   DELETE /api/wishlist/:productId
 * @desc    Remove a product from wishlist
 * @access  Private
 */
router.delete('/:productId', protect, async (req, res, next) => {
  try {
    const { productId } = req.params;
    const userId = req.user.uid;

    const wishlistRef = db.collection('wishlists').doc(userId);
    const wishlistDoc = await wishlistRef.get();

    if (!wishlistDoc.exists) {
      return next(new AppError('Wishlist not found', 404));
    }

    const wishlist = wishlistDoc.data();
    if (!wishlist.products.includes(productId)) {
      return next(new AppError('Product not in wishlist', 404));
    }

    // Remove product from wishlist
    await wishlistRef.update({
      products: wishlist.products.filter(id => id !== productId),
      updatedAt: new Date().toISOString()
    });

    res.status(200).json({
      success: true,
      message: 'Product removed from wishlist'
    });
  } catch (error) {
    console.error('Remove from wishlist error:', error);
    next(new AppError('Failed to remove product from wishlist', 500));
  }
});

/**
 * @route   DELETE /api/wishlist
 * @desc    Clear wishlist
 * @access  Private
 */
router.delete('/', protect, async (req, res, next) => {
  try {
    const userId = req.user.uid;

    const wishlistRef = db.collection('wishlists').doc(userId);
    const wishlistDoc = await wishlistRef.get();

    if (!wishlistDoc.exists) {
      return next(new AppError('Wishlist not found', 404));
    }

    // Clear wishlist
    await wishlistRef.update({
      products: [],
      updatedAt: new Date().toISOString()
    });

    res.status(200).json({
      success: true,
      message: 'Wishlist cleared'
    });
  } catch (error) {
    console.error('Clear wishlist error:', error);
    next(new AppError('Failed to clear wishlist', 500));
  }
});

export default router;