import express from 'express';
const router = express.Router();

// Import Firebase config
import { db } from '../config/firebase.js';

// Import middleware
import { protect, authorize } from '../middleware/auth.js';

/**
 * @route   GET /api/analytics/sales
 * @desc    Get sales analytics
 * @access  Private (Admin, Manager)
 */
router.get('/sales', protect, authorize('admin', 'manager'), async (req, res, next) => {
  try {
    const { period = 'month' } = req.query;
    
    // Calculate date range based on period
    const now = new Date();
    let startDate;
    
    switch(period) {
      case 'day':
        startDate = new Date(now.setHours(0, 0, 0, 0));
        break;
      case 'week':
        const day = now.getDay();
        startDate = new Date(now.setDate(now.getDate() - day));
        startDate.setHours(0, 0, 0, 0);
        break;
      case 'month':
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        break;
      case 'year':
        startDate = new Date(now.getFullYear(), 0, 1);
        break;
      default:
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
    }
    
    // Convert to ISO string for Firestore query
    const startDateStr = startDate.toISOString();
    
    // Get orders within the date range
    const ordersSnapshot = await db.collection('orders')
      .where('createdAt', '>=', startDateStr)
      .get();
    
    // Calculate analytics
    let totalSales = 0;
    let totalOrders = 0;
    let productsSold = 0;
    const productSales = {};
    
    ordersSnapshot.forEach(doc => {
      const orderData = doc.data();
      
      // Only count completed orders
      if (orderData.status !== 'cancelled') {
        totalSales += orderData.total;
        totalOrders++;
        
        // Count products sold and track sales by product
        orderData.items.forEach(item => {
          productsSold += item.quantity;
          
          // Track sales by product
          if (productSales[item.productId]) {
            productSales[item.productId].quantity += item.quantity;
            productSales[item.productId].revenue += item.itemTotal;
          } else {
            productSales[item.productId] = {
              productId: item.productId,
              productName: item.productName,
              quantity: item.quantity,
              revenue: item.itemTotal
            };
          }
        });
      }
    });
    
    // Convert product sales to array and sort by revenue
    const topProducts = Object.values(productSales)
      .sort((a, b) => b.revenue - a.revenue)
      .slice(0, 5);
    
    res.status(200).json({
      success: true,
      data: {
        period,
        totalSales,
        totalOrders,
        productsSold,
        averageOrderValue: totalOrders > 0 ? totalSales / totalOrders : 0,
        topProducts
      }
    });
  } catch (error) {
    console.error('Get sales analytics error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/analytics/inventory
 * @desc    Get inventory analytics
 * @access  Private (Admin, Manager)
 */
router.get('/inventory', protect, authorize('admin', 'manager'), async (req, res, next) => {
  try {
    const productsSnapshot = await db.collection('products').get();
    
    // Calculate inventory analytics
    let totalProducts = 0;
    let totalValue = 0;
    let lowStockProducts = 0;
    const lowStockItems = [];
    
    productsSnapshot.forEach(doc => {
      const productData = doc.data();
      totalProducts++;
      totalValue += productData.price * productData.stockQuantity;
      
      // Check for low stock (less than 10 items)
      if (productData.stockQuantity < 10) {
        lowStockProducts++;
        lowStockItems.push({
          id: doc.id,
          name: productData.name,
          stockQuantity: productData.stockQuantity,
          category: productData.category
        });
      }
    });
    
    res.status(200).json({
      success: true,
      data: {
        totalProducts,
        totalValue,
        lowStockProducts,
        lowStockItems
      }
    });
  } catch (error) {
    console.error('Get inventory analytics error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/analytics/users
 * @desc    Get user analytics
 * @access  Private (Admin)
 */
router.get('/users', protect, authorize('admin'), async (req, res, next) => {
  try {
    const usersSnapshot = await db.collection('users').get();
    
    // Calculate user analytics
    const totalUsers = usersSnapshot.size;
    let usersByRole = {
      admin: 0,
      manager: 0,
      staff: 0
    };
    
    usersSnapshot.forEach(doc => {
      const userData = doc.data();
      if (userData.role && usersByRole.hasOwnProperty(userData.role)) {
        usersByRole[userData.role]++;
      }
    });
    
    res.status(200).json({
      success: true,
      data: {
        totalUsers,
        usersByRole
      }
    });
  } catch (error) {
    console.error('Get user analytics error:', error);
    next(error);
  }
});

export default router;