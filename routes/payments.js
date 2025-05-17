const express = require('express');
const { body } = require('express-validator');
const validateRequest = require('../middleware/validateRequest');
const { protect } = require('../middleware/auth');
const crypto = require('crypto');
const router = express.Router();

// Initialize Paystack
const paystack = require('paystack')(process.env.PAYSTACK_SECRET_KEY);

/**
 * @route   POST /api/payments/initialize
 * @desc    Initialize a payment transaction
 * @access  Private
 */
router.post('/initialize', [
  body('email').isEmail().withMessage('Valid email is required'),
  body('amount').isNumeric().withMessage('Amount must be a number'),
  body('reference').optional().isString().withMessage('Reference must be a string'),
  body('callback_url').optional().isURL().withMessage('Callback URL must be valid')
], validateRequest, protect, async (req, res, next) => {
  try {
    const { email, amount, reference, callback_url, metadata } = req.body;
    
    // Amount should be in kobo (multiply by 100)
    const amountInKobo = Math.round(amount * 100);
    
    const initializeOptions = {
      email,
      amount: amountInKobo,
      reference: reference || `REF-${Date.now()}-${Math.floor(Math.random() * 1000000)}`,
      callback_url: callback_url || process.env.FRONTEND_URL + '/payment/callback',
      metadata: {
        user_id: req.user.uid,
        ...metadata
      }
    };
    
    const response = await paystack.transaction.initialize(initializeOptions);
    
    res.status(200).json({
      success: true,
      data: response.data
    });
  } catch (error) {
    console.error('Payment initialization error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/payments/verify/:reference
 * @desc    Verify a payment transaction
 * @access  Private
 */
router.get('/verify/:reference', protect, async (req, res, next) => {
  try {
    const { reference } = req.params;
    
    const response = await paystack.transaction.verify(reference);
    
    if (response.data.status === 'success') {
      // Here you would update your database to mark the order as paid
      // This is where you'd implement order fulfillment logic
      
      res.status(200).json({
        success: true,
        message: 'Payment verified successfully',
        data: response.data
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Payment verification failed',
        data: response.data
      });
    }
  } catch (error) {
    console.error('Payment verification error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/payments/webhook
 * @desc    Handle Paystack webhook
 * @access  Public (but verified with Paystack signature)
 */
router.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
  try {
    const hash = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
                       .update(JSON.stringify(req.body))
                       .digest('hex');
    
    if (hash !== req.headers['x-paystack-signature']) {
      return res.status(400).send('Invalid signature');
    }
    
    const event = req.body;
    
    // Handle different event types
    switch(event.event) {
      case 'charge.success':
        // Handle successful charge
        console.log('Payment successful:', event.data);
        // Update order status in your database
        break;
        
      case 'transfer.success':
        // Handle successful transfer
        console.log('Transfer successful:', event.data);
        break;
        
      case 'transfer.failed':
        // Handle failed transfer
        console.log('Transfer failed:', event.data);
        break;
        
      default:
        // Handle other events
        console.log('Unhandled event:', event.event);
    }
    
    res.status(200).send('Webhook received');
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).send('Webhook error');
  }
});

/**
 * @route   GET /api/payments/transactions
 * @desc    Get user's payment transactions
 * @access  Private
 */
router.get('/transactions', protect, async (req, res, next) => {
  try {
    // You can filter by customer email if needed
    const response = await paystack.transaction.list({ perPage: 20 });
    
    // Filter transactions for the current user
    // This is a simple example - in production you might want to query your database instead
    const userTransactions = response.data.filter(transaction => {
      return transaction.metadata && transaction.metadata.user_id === req.user.uid;
    });
    
    res.status(200).json({
      success: true,
      data: userTransactions
    });
  } catch (error) {
    console.error('Get transactions error:', error);
    next(error);
  }
});

module.exports = router;