const express = require('express');
const { body } = require('express-validator');
const router = express.Router();

// Import Firebase config
const { db } = require('../config/firebase');

// Import middleware
const { validateRequest } = require('../middleware/errorHandler');
const { protect, authorize } = require('../middleware/auth');

/**
 * @route   GET /api/products
 * @desc    Get all products
 * @access  Public
 */
router.get('/', async (req, res, next) => {
  try {
    const productsSnapshot = await db.collection('products').get();
    const products = [];
    
    productsSnapshot.forEach(doc => {
      products.push({
        id: doc.id,
        ...doc.data()
      });
    });

    res.status(200).json({
      success: true,
      count: products.length,
      data: products
    });
  } catch (error) {
    console.error('Get products error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/products/:id
 * @desc    Get single product
 * @access  Public
 */
router.get('/:id', async (req, res, next) => {
  try {
    const productDoc = await db.collection('products').doc(req.params.id).get();
    
    if (!productDoc.exists) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.status(200).json({
      success: true,
      data: {
        id: productDoc.id,
        ...productDoc.data()
      }
    });
  } catch (error) {
    console.error('Get product error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/products
 * @desc    Create a new product
 * @access  Private (Admin, Manager)
 */
router.post('/', [
  protect,
  authorize('admin', 'manager'),
  body('name').notEmpty().withMessage('Product name is required'),
  body('description').notEmpty().withMessage('Description is required'),
  body('price').isNumeric().withMessage('Price must be a number'),
  body('category').notEmpty().withMessage('Category is required'),
  body('imageUrl').optional().isURL().withMessage('Image URL must be valid'),
  body('stockQuantity').isInt({ min: 0 }).withMessage('Stock quantity must be a positive integer')
], validateRequest, async (req, res, next) => {
  try {
    const { name, description, price, category, imageUrl, stockQuantity } = req.body;

    // Create product in Firestore
    const productRef = await db.collection('products').add({
      name,
      description,
      price: Number(price),
      category,
      imageUrl: imageUrl || '',
      stockQuantity: Number(stockQuantity),
      createdAt: new Date().toISOString(),
      createdBy: req.user.uid
    });

    // Get the created product
    const productDoc = await productRef.get();

    res.status(201).json({
      success: true,
      data: {
        id: productDoc.id,
        ...productDoc.data()
      }
    });
  } catch (error) {
    console.error('Create product error:', error);
    next(error);
  }
});

/**
 * @route   PUT /api/products/:id
 * @desc    Update a product
 * @access  Private (Admin, Manager)
 */
router.put('/:id', [
  protect,
  authorize('admin', 'manager'),
  body('name').optional().notEmpty().withMessage('Product name cannot be empty'),
  body('price').optional().isNumeric().withMessage('Price must be a number'),
  body('stockQuantity').optional().isInt({ min: 0 }).withMessage('Stock quantity must be a positive integer')
], validateRequest, async (req, res, next) => {
  try {
    // Check if product exists
    const productDoc = await db.collection('products').doc(req.params.id).get();
    
    if (!productDoc.exists) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Update product
    await db.collection('products').doc(req.params.id).update({
      ...req.body,
      updatedAt: new Date().toISOString(),
      updatedBy: req.user.uid
    });

    // Get updated product
    const updatedProductDoc = await db.collection('products').doc(req.params.id).get();

    res.status(200).json({
      success: true,
      data: {
        id: updatedProductDoc.id,
        ...updatedProductDoc.data()
      }
    });
  } catch (error) {
    console.error('Update product error:', error);
    next(error);
  }
});

/**
 * @route   DELETE /api/products/:id
 * @desc    Delete a product
 * @access  Private (Admin)
 */
router.delete('/:id', protect, authorize('admin'), async (req, res, next) => {
  try {
    // Check if product exists
    const productDoc = await db.collection('products').doc(req.params.id).get();
    
    if (!productDoc.exists) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Delete product
    await db.collection('products').doc(req.params.id).delete();

    res.status(200).json({
      success: true,
      message: 'Product deleted successfully'
    });
  } catch (error) {
    console.error('Delete product error:', error);
    next(error);
  }
});

module.exports = router;