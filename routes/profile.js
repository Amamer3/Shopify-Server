const express = require('express');
const { body } = require('express-validator');
const router = express.Router();

// Import Firebase config
const { db } = require('../config/firebase');

// Import middleware
const { validateRequest } = require('../middleware/errorHandler');
const { protect } = require('../middleware/auth');

/**
 * @route   GET /api/profile
 * @desc    Get user profile
 * @access  Private
 */
router.get('/', protect, async (req, res, next) => {
  try {
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'User profile not found' });
    }

    // Get user's addresses
    const addressesSnapshot = await db.collection('addresses')
      .where('userId', '==', req.user.uid)
      .get();
    
    const addresses = [];
    addressesSnapshot.forEach(doc => {
      addresses.push({
        id: doc.id,
        ...doc.data()
      });
    });

    // Get user's payment methods
    const paymentMethodsSnapshot = await db.collection('paymentMethods')
      .where('userId', '==', req.user.uid)
      .get();
    
    const paymentMethods = [];
    paymentMethodsSnapshot.forEach(doc => {
      const data = doc.data();
      // Mask card number for security
      if (data.cardNumber) {
        data.cardNumber = `**** **** **** ${data.cardNumber.slice(-4)}`;
      }
      paymentMethods.push({
        id: doc.id,
        ...data
      });
    });

    // Get user's order history
    const ordersSnapshot = await db.collection('orders')
      .where('userId', '==', req.user.uid)
      .orderBy('createdAt', 'desc')
      .limit(10)
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
      data: {
        profile: {
          id: userDoc.id,
          ...userDoc.data()
        },
        addresses,
        paymentMethods,
        recentOrders: orders
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    next(error);
  }
});

/**
 * @route   PUT /api/profile
 * @desc    Update user profile
 * @access  Private
 */
router.put('/', [
  protect,
  body('name').optional(),
  body('phone').optional(),
  body('preferences').optional()
], validateRequest, async (req, res, next) => {
  try {
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ message: 'User profile not found' });
    }

    const { name, phone, preferences } = req.body;
    const updateData = {};

    // Only update fields that are provided
    if (name) updateData.name = name;
    if (phone) updateData.phone = phone;
    if (preferences) updateData.preferences = preferences;

    updateData.updatedAt = new Date().toISOString();

    // Update user profile
    await db.collection('users').doc(req.user.uid).update(updateData);

    // Get updated profile
    const updatedUserDoc = await db.collection('users').doc(req.user.uid).get();

    res.status(200).json({
      success: true,
      data: {
        id: updatedUserDoc.id,
        ...updatedUserDoc.data()
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/profile/addresses
 * @desc    Add a new address
 * @access  Private
 */
router.post('/addresses', [
  protect,
  body('addressLine1').notEmpty().withMessage('Address line 1 is required'),
  body('city').notEmpty().withMessage('City is required'),
  body('state').notEmpty().withMessage('State is required'),
  body('postalCode').notEmpty().withMessage('Postal code is required'),
  body('country').notEmpty().withMessage('Country is required'),
  body('isDefault').optional().isBoolean()
], validateRequest, async (req, res, next) => {
  try {
    const { 
      addressLine1, 
      addressLine2, 
      city, 
      state, 
      postalCode, 
      country, 
      isDefault = false 
    } = req.body;

    // If this is the default address, update any existing default address
    if (isDefault) {
      const defaultAddressSnapshot = await db.collection('addresses')
        .where('userId', '==', req.user.uid)
        .where('isDefault', '==', true)
        .get();
      
      // Update existing default addresses to non-default
      const batch = db.batch();
      defaultAddressSnapshot.forEach(doc => {
        batch.update(doc.ref, { isDefault: false });
      });
      await batch.commit();
    }

    // Create new address
    const addressRef = db.collection('addresses').doc();
    const addressData = {
      userId: req.user.uid,
      addressLine1,
      addressLine2: addressLine2 || '',
      city,
      state,
      postalCode,
      country,
      isDefault,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    await addressRef.set(addressData);

    res.status(201).json({
      success: true,
      data: {
        id: addressRef.id,
        ...addressData
      }
    });
  } catch (error) {
    console.error('Add address error:', error);
    next(error);
  }
});

/**
 * @route   PUT /api/profile/addresses/:id
 * @desc    Update an address
 * @access  Private
 */
router.put('/addresses/:id', [
  protect,
  body('addressLine1').optional(),
  body('city').optional(),
  body('state').optional(),
  body('postalCode').optional(),
  body('country').optional(),
  body('isDefault').optional().isBoolean()
], validateRequest, async (req, res, next) => {
  try {
    const addressDoc = await db.collection('addresses').doc(req.params.id).get();
    
    if (!addressDoc.exists) {
      return res.status(404).json({ message: 'Address not found' });
    }

    // Check if address belongs to user
    const addressData = addressDoc.data();
    if (addressData.userId !== req.user.uid) {
      return res.status(403).json({ message: 'Not authorized to update this address' });
    }

    const { 
      addressLine1, 
      addressLine2, 
      city, 
      state, 
      postalCode, 
      country, 
      isDefault 
    } = req.body;

    const updateData = {};

    // Only update fields that are provided
    if (addressLine1) updateData.addressLine1 = addressLine1;
    if (addressLine2 !== undefined) updateData.addressLine2 = addressLine2;
    if (city) updateData.city = city;
    if (state) updateData.state = state;
    if (postalCode) updateData.postalCode = postalCode;
    if (country) updateData.country = country;
    
    // Handle default address update
    if (isDefault !== undefined) {
      updateData.isDefault = isDefault;
      
      // If setting as default, update any existing default address
      if (isDefault && !addressData.isDefault) {
        const defaultAddressSnapshot = await db.collection('addresses')
          .where('userId', '==', req.user.uid)
          .where('isDefault', '==', true)
          .get();
        
        // Update existing default addresses to non-default
        const batch = db.batch();
        defaultAddressSnapshot.forEach(doc => {
          batch.update(doc.ref, { isDefault: false });
        });
        await batch.commit();
      }
    }

    updateData.updatedAt = new Date().toISOString();

    // Update address
    await db.collection('addresses').doc(req.params.id).update(updateData);

    // Get updated address
    const updatedAddressDoc = await db.collection('addresses').doc(req.params.id).get();

    res.status(200).json({
      success: true,
      data: {
        id: updatedAddressDoc.id,
        ...updatedAddressDoc.data()
      }
    });
  } catch (error) {
    console.error('Update address error:', error);
    next(error);
  }
});

/**
 * @route   DELETE /api/profile/addresses/:id
 * @desc    Delete an address
 * @access  Private
 */
router.delete('/addresses/:id', protect, async (req, res, next) => {
  try {
    const addressDoc = await db.collection('addresses').doc(req.params.id).get();
    
    if (!addressDoc.exists) {
      return res.status(404).json({ message: 'Address not found' });
    }

    // Check if address belongs to user
    const addressData = addressDoc.data();
    if (addressData.userId !== req.user.uid) {
      return res.status(403).json({ message: 'Not authorized to delete this address' });
    }

    // Delete address
    await db.collection('addresses').doc(req.params.id).delete();

    res.status(200).json({
      success: true,
      message: 'Address deleted successfully'
    });
  } catch (error) {
    console.error('Delete address error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/profile/payment-methods
 * @desc    Add a new payment method
 * @access  Private
 */
router.post('/payment-methods', [
  protect,
  body('type').isIn(['credit_card', 'paypal']).withMessage('Invalid payment method type'),
  body('cardNumber').if(body('type').equals('credit_card')).notEmpty().withMessage('Card number is required for credit card'),
  body('cardholderName').if(body('type').equals('credit_card')).notEmpty().withMessage('Cardholder name is required'),
  body('expiryMonth').if(body('type').equals('credit_card')).isInt({ min: 1, max: 12 }).withMessage('Valid expiry month is required'),
  body('expiryYear').if(body('type').equals('credit_card')).isInt({ min: new Date().getFullYear() }).withMessage('Valid expiry year is required'),
  body('paypalEmail').if(body('type').equals('paypal')).isEmail().withMessage('Valid PayPal email is required'),
  body('isDefault').optional().isBoolean()
], validateRequest, async (req, res, next) => {
  try {
    const { 
      type, 
      cardNumber, 
      cardholderName, 
      expiryMonth, 
      expiryYear, 
      paypalEmail, 
      isDefault = false 
    } = req.body;

    // If this is the default payment method, update any existing default
    if (isDefault) {
      const defaultPaymentMethodSnapshot = await db.collection('paymentMethods')
        .where('userId', '==', req.user.uid)
        .where('isDefault', '==', true)
        .get();
      
      // Update existing default payment methods to non-default
      const batch = db.batch();
      defaultPaymentMethodSnapshot.forEach(doc => {
        batch.update(doc.ref, { isDefault: false });
      });
      await batch.commit();
    }

    // Create new payment method
    const paymentMethodRef = db.collection('paymentMethods').doc();
    const paymentMethodData = {
      userId: req.user.uid,
      type,
      isDefault,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // Add type-specific fields
    if (type === 'credit_card') {
      paymentMethodData.cardNumber = cardNumber;
      paymentMethodData.cardholderName = cardholderName;
      paymentMethodData.expiryMonth = expiryMonth;
      paymentMethodData.expiryYear = expiryYear;
    } else if (type === 'paypal') {
      paymentMethodData.paypalEmail = paypalEmail;
    }

    await paymentMethodRef.set(paymentMethodData);

    // Mask card number for response
    if (paymentMethodData.cardNumber) {
      paymentMethodData.cardNumber = `**** **** **** ${paymentMethodData.cardNumber.slice(-4)}`;
    }

    res.status(201).json({
      success: true,
      data: {
        id: paymentMethodRef.id,
        ...paymentMethodData
      }
    });
  } catch (error) {
    console.error('Add payment method error:', error);
    next(error);
  }
});

/**
 * @route   DELETE /api/profile/payment-methods/:id
 * @desc    Delete a payment method
 * @access  Private
 */
router.delete('/payment-methods/:id', protect, async (req, res, next) => {
  try {
    const paymentMethodDoc = await db.collection('paymentMethods').doc(req.params.id).get();
    
    if (!paymentMethodDoc.exists) {
      return res.status(404).json({ message: 'Payment method not found' });
    }

    // Check if payment method belongs to user
    const paymentMethodData = paymentMethodDoc.data();
    if (paymentMethodData.userId !== req.user.uid) {
      return res.status(403).json({ message: 'Not authorized to delete this payment method' });
    }

    // Delete payment method
    await db.collection('paymentMethods').doc(req.params.id).delete();

    res.status(200).json({
      success: true,
      message: 'Payment method deleted successfully'
    });
  } catch (error) {
    console.error('Delete payment method error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/profile/orders
 * @desc    Get user's order history
 * @access  Private
 */
router.get('/orders', protect, async (req, res, next) => {
  try {
    // Pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const startAt = (page - 1) * limit;

    // Get total count
    const countSnapshot = await db.collection('orders')
      .where('userId', '==', req.user.uid)
      .get();
    
    const totalOrders = countSnapshot.size;

    // Get paginated orders
    const ordersSnapshot = await db.collection('orders')
      .where('userId', '==', req.user.uid)
      .orderBy('createdAt', 'desc')
      .limit(limit)
      .offset(startAt)
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
      totalOrders,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(totalOrders / limit),
        limit
      },
      data: orders
    });
  } catch (error) {
    console.error('Get order history error:', error);
    next(error);
  }
});

module.exports = router;