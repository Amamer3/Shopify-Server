const express = require('express');
const { body } = require('express-validator');
const router = express.Router();

// Import Firebase config
const { db } = require('../config/firebase');

// Import middleware
const { validateRequest } = require('../middleware/errorHandler');
const { protect } = require('../middleware/auth');

/**
 * @route   GET /api/cart
 * @desc    Get user's cart
 * @access  Private
 */
router.get('/', protect, async (req, res, next) => {
  try {
    const cartRef = db.collection('carts').doc(req.user.uid);
    const cartDoc = await cartRef.get();
    
    if (!cartDoc.exists) {
      return res.status(200).json({
        success: true,
        data: {
          items: [],
          totalItems: 0,
          totalPrice: 0
        }
      });
    }

    const cartData = cartDoc.data();
    
    // Calculate totals
    let totalItems = 0;
    let totalPrice = 0;
    
    if (cartData.items && cartData.items.length > 0) {
      // Get all product IDs from cart
      const productIds = cartData.items.map(item => item.productId);
      
      // Get all products in a single batch query
      const productsSnapshot = await db.collection('products')
        .where('__name__', 'in', productIds)
        .get();
      
      // Create a map of products for easy lookup
      const productsMap = {};
      productsSnapshot.forEach(doc => {
        productsMap[doc.id] = doc.data();
      });
      
      // Update cart items with current product data
      const updatedItems = cartData.items.map(item => {
        const product = productsMap[item.productId];
        if (!product) return null; // Product no longer exists
        
        // Check if requested quantity is available
        const availableQuantity = product.stockQuantity || 0;
        const quantity = Math.min(item.quantity, availableQuantity);
        
        // Calculate item total
        const itemPrice = product.price * quantity;
        totalItems += quantity;
        totalPrice += itemPrice;
        
        return {
          productId: item.productId,
          name: product.name,
          price: product.price,
          quantity,
          imageUrl: product.imageUrl,
          stockQuantity: availableQuantity,
          itemTotal: itemPrice
        };
      }).filter(Boolean); // Remove null items (deleted products)
      
      // Return updated cart
      return res.status(200).json({
        success: true,
        data: {
          items: updatedItems,
          totalItems,
          totalPrice
        }
      });
    } else {
      // Empty cart
      return res.status(200).json({
        success: true,
        data: {
          items: [],
          totalItems: 0,
          totalPrice: 0
        }
      });
    }
  } catch (error) {
    console.error('Get cart error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/cart
 * @desc    Add item to cart
 * @access  Private
 */
router.post('/', [
  protect,
  body('productId').notEmpty().withMessage('Product ID is required'),
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1')
], validateRequest, async (req, res, next) => {
  try {
    const { productId, quantity } = req.body;
    
    // Check if product exists and has enough stock
    const productDoc = await db.collection('products').doc(productId).get();
    
    if (!productDoc.exists) {
      return res.status(404).json({ message: 'Product not found' });
    }
    
    const product = productDoc.data();
    
    if (product.stockQuantity < quantity) {
      return res.status(400).json({ 
        message: `Not enough stock. Only ${product.stockQuantity} available.` 
      });
    }
    
    // Get user's cart or create if it doesn't exist
    const cartRef = db.collection('carts').doc(req.user.uid);
    const cartDoc = await cartRef.get();
    
    if (!cartDoc.exists) {
      // Create new cart
      await cartRef.set({
        userId: req.user.uid,
        items: [{
          productId,
          quantity,
          addedAt: new Date().toISOString()
        }],
        updatedAt: new Date().toISOString()
      });
    } else {
      // Update existing cart
      const cartData = cartDoc.data();
      const items = cartData.items || [];
      
      // Check if product already in cart
      const existingItemIndex = items.findIndex(item => item.productId === productId);
      
      if (existingItemIndex >= 0) {
        // Update quantity of existing item
        items[existingItemIndex].quantity += quantity;
        items[existingItemIndex].updatedAt = new Date().toISOString();
      } else {
        // Add new item to cart
        items.push({
          productId,
          quantity,
          addedAt: new Date().toISOString()
        });
      }
      
      // Update cart in database
      await cartRef.update({
        items,
        updatedAt: new Date().toISOString()
      });
    }
    
    // Return updated cart
    const updatedCartDoc = await cartRef.get();
    
    res.status(200).json({
      success: true,
      message: 'Item added to cart',
      data: updatedCartDoc.data()
    });
  } catch (error) {
    console.error('Add to cart error:', error);
    next(error);
  }
});

/**
 * @route   PUT /api/cart/:productId
 * @desc    Update cart item quantity
 * @access  Private
 */
router.put('/:productId', [
  protect,
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1')
], validateRequest, async (req, res, next) => {
  try {
    const { productId } = req.params;
    const { quantity } = req.body;
    
    // Check if product exists and has enough stock
    const productDoc = await db.collection('products').doc(productId).get();
    
    if (!productDoc.exists) {
      return res.status(404).json({ message: 'Product not found' });
    }
    
    const product = productDoc.data();
    
    if (product.stockQuantity < quantity) {
      return res.status(400).json({ 
        message: `Not enough stock. Only ${product.stockQuantity} available.` 
      });
    }
    
    // Get user's cart
    const cartRef = db.collection('carts').doc(req.user.uid);
    const cartDoc = await cartRef.get();
    
    if (!cartDoc.exists) {
      return res.status(404).json({ message: 'Cart not found' });
    }
    
    // Update cart item quantity
    const cartData = cartDoc.data();
    const items = cartData.items || [];
    
    const existingItemIndex = items.findIndex(item => item.productId === productId);
    
    if (existingItemIndex === -1) {
      return res.status(404).json({ message: 'Item not found in cart' });
    }
    
    // Update quantity
    items[existingItemIndex].quantity = quantity;
    items[existingItemIndex].updatedAt = new Date().toISOString();
    
    // Update cart in database
    await cartRef.update({
      items,
      updatedAt: new Date().toISOString()
    });
    
    // Return updated cart
    const updatedCartDoc = await cartRef.get();
    
    res.status(200).json({
      success: true,
      message: 'Cart updated',
      data: updatedCartDoc.data()
    });
  } catch (error) {
    console.error('Update cart error:', error);
    next(error);
  }
});

/**
 * @route   DELETE /api/cart/:productId
 * @desc    Remove item from cart
 * @access  Private
 */
router.delete('/:productId', protect, async (req, res, next) => {
  try {
    const { productId } = req.params;
    
    // Get user's cart
    const cartRef = db.collection('carts').doc(req.user.uid);
    const cartDoc = await cartRef.get();
    
    if (!cartDoc.exists) {
      return res.status(404).json({ message: 'Cart not found' });
    }
    
    // Remove item from cart
    const cartData = cartDoc.data();
    const items = cartData.items || [];
    
    const updatedItems = items.filter(item => item.productId !== productId);
    
    if (items.length === updatedItems.length) {
      return res.status(404).json({ message: 'Item not found in cart' });
    }
    
    // Update cart in database
    await cartRef.update({
      items: updatedItems,
      updatedAt: new Date().toISOString()
    });
    
    res.status(200).json({
      success: true,
      message: 'Item removed from cart'
    });
  } catch (error) {
    console.error('Remove from cart error:', error);
    next(error);
  }
});

/**
 * @route   DELETE /api/cart
 * @desc    Clear cart
 * @access  Private
 */
router.delete('/', protect, async (req, res, next) => {
  try {
    // Get user's cart
    const cartRef = db.collection('carts').doc(req.user.uid);
    const cartDoc = await cartRef.get();
    
    if (!cartDoc.exists) {
      return res.status(404).json({ message: 'Cart not found' });
    }
    
    // Clear cart items
    await cartRef.update({
      items: [],
      updatedAt: new Date().toISOString()
    });
    
    res.status(200).json({
      success: true,
      message: 'Cart cleared'
    });
  } catch (error) {
    console.error('Clear cart error:', error);
    next(error);
  }
});

module.exports = router;