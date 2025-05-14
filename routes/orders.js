const express = require('express');
const { body } = require('express-validator');
const router = express.Router();

// Import Firebase config
const { db } = require('../config/firebase');

// Import middleware
const { validateRequest } = require('../middleware/errorHandler');
const { protect, authorize } = require('../middleware/auth');

/**
 * @route   GET /api/orders
 * @desc    Get all orders
 * @access  Private (Admin, Manager)
 */
router.get('/', protect, authorize('admin', 'manager'), async (req, res, next) => {
  try {
    const ordersSnapshot = await db.collection('orders').get();
    const orders = [];
    
    ordersSnapshot.forEach(doc => {
      orders.push({
        id: doc.id,
        ...doc.data()
      });
    });

    res.status(200).json({
      success: true,
      count: orders.length,
      data: orders
    });
  } catch (error) {
    console.error('Get orders error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/orders/my-orders
 * @desc    Get orders for the current user
 * @access  Private
 */
router.get('/my-orders', protect, async (req, res, next) => {
  try {
    const ordersSnapshot = await db.collection('orders')
      .where('userId', '==', req.user.uid)
      .get();
    
    const orders = [];
    
    ordersSnapshot.forEach(doc => {
      orders.push({
        id: doc.id,
        ...doc.data()
      });
    });

    res.status(200).json({
      success: true,
      count: orders.length,
      data: orders
    });
  } catch (error) {
    console.error('Get my orders error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/orders/:id
 * @desc    Get single order
 * @access  Private
 */
router.get('/:id', protect, async (req, res, next) => {
  try {
    const orderDoc = await db.collection('orders').doc(req.params.id).get();
    
    if (!orderDoc.exists) {
      return res.status(404).json({ message: 'Order not found' });
    }

    const orderData = orderDoc.data();

    // Check if the user is authorized to view this order
    if (orderData.userId !== req.user.uid && !['admin', 'manager'].includes(req.user.role)) {
      return res.status(403).json({ message: 'Not authorized to view this order' });
    }

    res.status(200).json({
      success: true,
      data: {
        id: orderDoc.id,
        ...orderData
      }
    });
  } catch (error) {
    console.error('Get order error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/orders
 * @desc    Create a new order
 * @access  Private
 */
router.post('/', [
  protect,
  body('items').isArray().withMessage('Items must be an array'),
  body('items.*.productId').notEmpty().withMessage('Product ID is required'),
  body('items.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
  body('shippingAddress').notEmpty().withMessage('Shipping address is required')
], validateRequest, async (req, res, next) => {
  try {
    const { items, shippingAddress, notes } = req.body;

    // Validate products and calculate total
    let total = 0;
    const orderItems = [];

    // Process each item in the order
    for (const item of items) {
      const productDoc = await db.collection('products').doc(item.productId).get();
      
      if (!productDoc.exists) {
        return res.status(404).json({ message: `Product ${item.productId} not found` });
      }

      const productData = productDoc.data();
      
      // Check if enough stock is available
      if (productData.stockQuantity < item.quantity) {
        return res.status(400).json({ 
          message: `Not enough stock for ${productData.name}. Available: ${productData.stockQuantity}` 
        });
      }

      // Calculate item total
      const itemTotal = productData.price * item.quantity;
      
      // Add to order items
      orderItems.push({
        productId: item.productId,
        productName: productData.name,
        quantity: item.quantity,
        price: productData.price,
        itemTotal
      });

      // Add to order total
      total += itemTotal;

      // Update product stock
      await db.collection('products').doc(item.productId).update({
        stockQuantity: productData.stockQuantity - item.quantity
      });
    }

    // Create order in Firestore
    const orderRef = await db.collection('orders').add({
      userId: req.user.uid,
      items: orderItems,
      total,
      status: 'pending',
      shippingAddress,
      notes: notes || '',
      createdAt: new Date().toISOString()
    });

    // Get the created order
    const orderDoc = await orderRef.get();

    res.status(201).json({
      success: true,
      data: {
        id: orderDoc.id,
        ...orderDoc.data()
      }
    });
  } catch (error) {
    console.error('Create order error:', error);
    next(error);
  }
});

/**
 * @route   PUT /api/orders/:id/status
 * @desc    Update order status
 * @access  Private (Admin, Manager)
 */
router.put('/:id/status', [
  protect,
  authorize('admin', 'manager'),
  body('status').isIn(['pending', 'processing', 'shipped', 'delivered', 'cancelled'])
    .withMessage('Invalid status')
], validateRequest, async (req, res, next) => {
  try {
    const { status } = req.body;

    // Check if order exists
    const orderDoc = await db.collection('orders').doc(req.params.id).get();
    
    if (!orderDoc.exists) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Update order status
    await db.collection('orders').doc(req.params.id).update({
      status,
      updatedAt: new Date().toISOString(),
      updatedBy: req.user.uid
    });

    // Get updated order
    const updatedOrderDoc = await db.collection('orders').doc(req.params.id).get();

    res.status(200).json({
      success: true,
      data: {
        id: updatedOrderDoc.id,
        ...updatedOrderDoc.data()
      }
    });
  } catch (error) {
    console.error('Update order status error:', error);
    next(error);
  }
});

/**
 * @route   DELETE /api/orders/:id
 * @desc    Delete an order
 * @access  Private (Admin)
 */
router.delete('/:id', protect, authorize('admin'), async (req, res, next) => {
  try {
    // Check if order exists
    const orderDoc = await db.collection('orders').doc(req.params.id).get();
    
    if (!orderDoc.exists) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Delete order
    await db.collection('orders').doc(req.params.id).delete();

    res.status(200).json({
      success: true,
      message: 'Order deleted successfully'
    });
  } catch (error) {
    console.error('Delete order error:', error);
    next(error);
  }
});

module.exports = router;