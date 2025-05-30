import express from 'express';
import { body } from 'express-validator';
const router = express.Router();

// Import Firebase config
import { db } from '../config/firebase.js';

// Import middleware
import { validateRequest } from '../middleware/errorHandler.js';
import { protect, authorize } from '../middleware/auth.js';

/**
 * @route   GET /api/inventory
 * @desc    Get inventory status for all products
 * @access  Private (Admin, Superadmin)
 */
router.get('/', protect, async (req, res, next) => {
  try {
    const productsSnapshot = await db.collection('products').get();
    const inventory = [];
    
    productsSnapshot.forEach(doc => {
      const productData = doc.data();
      inventory.push({
        id: doc.id,
        name: productData.name,
        stockQuantity: productData.stockQuantity,
        category: productData.category,
        price: productData.price,
        status: productData.stockQuantity > 10 ? 'In Stock' : 
                productData.stockQuantity > 0 ? 'Low Stock' : 'Out of Stock'
      });
    });

    res.status(200).json({
      success: true,
      count: inventory.length,
      data: inventory
    });
  } catch (error) {
    console.error('Get inventory error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/inventory/low-stock
 * @desc    Get products with low stock
 * @access  Private (Admin, Superadmin)
 */
router.get('/low-stock', protect, async (req, res, next) => {
  try {
    const productsSnapshot = await db.collection('products')
      .where('stockQuantity', '<', 10)
      .get();
    
    const lowStockItems = [];
    
    productsSnapshot.forEach(doc => {
      const productData = doc.data();
      lowStockItems.push({
        id: doc.id,
        name: productData.name,
        stockQuantity: productData.stockQuantity,
        category: productData.category,
        status: productData.stockQuantity > 0 ? 'Low Stock' : 'Out of Stock'
      });
    });

    res.status(200).json({
      success: true,
      count: lowStockItems.length,
      data: lowStockItems
    });
  } catch (error) {
    console.error('Get low stock items error:', error);
    next(error);
  }
});

/**
 * @route   PUT /api/inventory/:id
 * @desc    Update product inventory
 * @access  Private (Admin, Superadmin)
 */
router.put('/:id', [
  protect,
  authorize('admin', 'superadmin'),
  body('stockQuantity').isInt({ min: 0 }).withMessage('Stock quantity must be a positive integer')
], validateRequest, async (req, res, next) => {
  try {
    const { stockQuantity } = req.body;

    // Check if product exists
    const productDoc = await db.collection('products').doc(req.params.id).get();
    
    if (!productDoc.exists) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Update product stock
    await db.collection('products').doc(req.params.id).update({
      stockQuantity: Number(stockQuantity),
      updatedAt: new Date().toISOString(),
      updatedBy: req.user.uid
    });

    // Get updated product
    const updatedProductDoc = await db.collection('products').doc(req.params.id).get();
    const updatedProductData = updatedProductDoc.data();

    res.status(200).json({
      success: true,
      data: {
        id: updatedProductDoc.id,
        name: updatedProductData.name,
        stockQuantity: updatedProductData.stockQuantity,
        status: updatedProductData.stockQuantity > 10 ? 'In Stock' : 
                updatedProductData.stockQuantity > 0 ? 'Low Stock' : 'Out of Stock'
      }
    });
  } catch (error) {
    console.error('Update inventory error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/inventory/bulk-update
 * @desc    Bulk update product inventory
 * @access  Private (Admin, Superadmin)
 */
router.post('/bulk-update', [
  protect,
  authorize('admin', 'superadmin'),
  body('items').isArray().withMessage('Items must be an array'),
  body('items.*.productId').notEmpty().withMessage('Product ID is required'),
  body('items.*.stockQuantity').isInt({ min: 0 }).withMessage('Stock quantity must be a positive integer')
], validateRequest, async (req, res, next) => {
  try {
    const { items } = req.body;
    const batch = db.batch();
    const updatedItems = [];
    const timestamp = new Date().toISOString();

    // Process each item in the bulk update
    for (const item of items) {
      const productRef = db.collection('products').doc(item.productId);
      const productDoc = await productRef.get();
      
      if (!productDoc.exists) {
        return res.status(404).json({ message: `Product ${item.productId} not found` });
      }

      // Add to batch update
      batch.update(productRef, {
        stockQuantity: Number(item.stockQuantity),
        updatedAt: timestamp,
        updatedBy: req.user.uid
      });

      updatedItems.push({
        productId: item.productId,
        name: productDoc.data().name,
        stockQuantity: Number(item.stockQuantity)
      });
    }

    // Commit the batch
    await batch.commit();

    res.status(200).json({
      success: true,
      message: `${updatedItems.length} products updated successfully`,
      data: updatedItems
    });
  } catch (error) {
    console.error('Bulk update inventory error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/inventory/history/:id
 * @desc    Get inventory history for a product
 * @access  Private (Admin, Superadmin)
 */
router.get('/history/:id', protect, authorize('admin', 'superadmin'), async (req, res, next) => {
  try {
    // Check if product exists
    const productDoc = await db.collection('products').doc(req.params.id).get();
    
    if (!productDoc.exists) {
      return res.status(404).json({ message: 'Product not found' });
    }

    // Get inventory history from a separate collection
    const historySnapshot = await db.collection('inventory_history')
      .where('productId', '==', req.params.id)
      .orderBy('timestamp', 'desc')
      .limit(20)
      .get();
    
    const history = [];
    
    historySnapshot.forEach(doc => {
      history.push({
        id: doc.id,
        ...doc.data()
      });
    });

    res.status(200).json({
      success: true,
      count: history.length,
      data: history
    });
  } catch (error) {
    console.error('Get inventory history error:', error);
    next(error);
  }
});

export default router;