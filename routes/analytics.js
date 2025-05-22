import express from 'express';
const router = express.Router();

// Import Firebase config
import { db } from '../config/firebase.js';

// Import middleware
import { protect, authorize } from '../middleware/auth.js';

/**
 * @route   GET /api/analytics/sales
 * @desc    Get sales analytics
 * @access  Private (Admin, Manager, Superadmin)
 */
router.get('/sales', protect, authorize('admin', 'manager', 'superadmin'), async (req, res, next) => {
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
    
    const startDateStr = startDate.toISOString();
    
    const ordersSnapshot = await db.collection('orders')
      .where('createdAt', '>=', startDateStr)
      .get();
    
    let totalSales = 0;
    let totalOrders = 0;
    let productsSold = 0;
    const productSales = {};
    
    ordersSnapshot.forEach(doc => {
      const orderData = doc.data();
      if (orderData.status !== 'cancelled') {
        totalSales += orderData.total;
        totalOrders++;
        orderData.items.forEach(item => {
          productsSold += item.quantity;
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
 * @route   GET /api/analytics/products
 * @desc    Get product performance analytics
 * @access  Private (Admin, Manager, Superadmin)
 */
router.get('/products', protect, authorize('admin', 'manager', 'superadmin'), async (req, res, next) => {
  try {
    const productsSnapshot = await db.collection('products').get();
    const ordersSnapshot = await db.collection('orders')
      .where('status', '!=', 'cancelled')
      .get();

    const productAnalytics = {};

    // Initialize product analytics
    productsSnapshot.forEach(doc => {
      const productData = doc.data();
      productAnalytics[doc.id] = {
        productId: doc.id,
        name: productData.name,
        category: productData.category,
        price: productData.price,
        stockQuantity: productData.stockQuantity,
        totalSales: 0,
        totalRevenue: 0,
        totalOrders: 0
      };
    });

    // Calculate sales metrics
    ordersSnapshot.forEach(doc => {
      const orderData = doc.data();
      orderData.items.forEach(item => {
        if (productAnalytics[item.productId]) {
          productAnalytics[item.productId].totalSales += item.quantity;
          productAnalytics[item.productId].totalRevenue += item.itemTotal;
          productAnalytics[item.productId].totalOrders++;
        }
      });
    });

    const productsArray = Object.values(productAnalytics)
      .map(product => ({
        ...product,
        averageOrderValue: product.totalOrders > 0 ? product.totalRevenue / product.totalOrders : 0
      }))
      .sort((a, b) => b.totalRevenue - a.totalRevenue);

    res.status(200).json({
      success: true,
      data: {
        products: productsArray,
        topPerformers: productsArray.slice(0, 5),
        lowPerformers: productsArray.slice(-5).reverse()
      }
    });
  } catch (error) {
    console.error('Get product analytics error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/analytics/customers
 * @desc    Get customer analytics
 * @access  Private (Admin, Manager, Superadmin)
 */
router.get('/customers', protect, authorize('admin', 'manager', 'superadmin'), async (req, res, next) => {
  try {
    const ordersSnapshot = await db.collection('orders')
      .where('status', '!=', 'cancelled')
      .get();

    const customerAnalytics = {};
    let totalCustomers = 0;

    ordersSnapshot.forEach(doc => {
      const orderData = doc.data();
      const customerId = orderData.userId;

      if (!customerAnalytics[customerId]) {
        customerAnalytics[customerId] = {
          customerId,
          totalOrders: 0,
          totalSpent: 0,
          lastOrderDate: null
        };
        totalCustomers++;
      }

      customerAnalytics[customerId].totalOrders++;
      customerAnalytics[customerId].totalSpent += orderData.total;
      
      const orderDate = new Date(orderData.createdAt);
      if (!customerAnalytics[customerId].lastOrderDate ||
          orderDate > new Date(customerAnalytics[customerId].lastOrderDate)) {
        customerAnalytics[customerId].lastOrderDate = orderData.createdAt;
      }
    });

    const customersArray = Object.values(customerAnalytics)
      .map(customer => ({
        ...customer,
        averageOrderValue: customer.totalSpent / customer.totalOrders
      }))
      .sort((a, b) => b.totalSpent - a.totalSpent);

    res.status(200).json({
      success: true,
      data: {
        totalCustomers,
        topCustomers: customersArray.slice(0, 10),
        averageCustomerMetrics: {
          ordersPerCustomer: customersArray.reduce((acc, curr) => acc + curr.totalOrders, 0) / totalCustomers,
          revenuePerCustomer: customersArray.reduce((acc, curr) => acc + curr.totalSpent, 0) / totalCustomers
        }
      }
    });
  } catch (error) {
    console.error('Get customer analytics error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/analytics/dashboard
 * @desc    Get dashboard overview statistics
 * @access  Private (Admin, Manager, Superadmin)
 */
router.get('/dashboard', protect, authorize('admin', 'manager', 'superadmin'), async (req, res, next) => {
  try {
    // Get current date and start of current month
    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();

    // Fetch recent orders
    const ordersSnapshot = await db.collection('orders')
      .where('createdAt', '>=', startOfMonth)
      .get();

    // Fetch inventory status
    const productsSnapshot = await db.collection('products').get();

    // Fetch users
    const usersSnapshot = await db.collection('users').get();

    // Calculate dashboard metrics
    let monthlyRevenue = 0;
    let monthlyOrders = 0;
    let lowStockProducts = 0;
    const recentOrders = [];

    // Process orders
    ordersSnapshot.forEach(doc => {
      const orderData = doc.data();
      if (orderData.status !== 'cancelled') {
        monthlyRevenue += orderData.total;
        monthlyOrders++;
      }
      if (recentOrders.length < 5) {
        recentOrders.push({
          id: doc.id,
          ...orderData
        });
      }
    });

    // Process inventory
    productsSnapshot.forEach(doc => {
      const productData = doc.data();
      if (productData.stockQuantity < 10) {
        lowStockProducts++;
      }
    });

    res.status(200).json({
      success: true,
      data: {
        monthlyMetrics: {
          revenue: monthlyRevenue,
          orders: monthlyOrders,
          averageOrderValue: monthlyOrders > 0 ? monthlyRevenue / monthlyOrders : 0
        },
        inventoryMetrics: {
          totalProducts: productsSnapshot.size,
          lowStockProducts
        },
        userMetrics: {
          totalUsers: usersSnapshot.size
        },
        recentOrders: recentOrders.sort((a, b) => 
          new Date(b.createdAt) - new Date(a.createdAt)
        )
      }
    });
  } catch (error) {
    console.error('Get dashboard analytics error:', error);
    next(error);
  }
});

export default router;