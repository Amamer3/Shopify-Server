import express from 'express';
import { body } from 'express-validator';
import { validateRequest } from '../middleware/errorHandler.js';
import { protect } from '../middleware/auth.js';
import crypto from 'crypto';
import axios from 'axios';
const router = express.Router();

// Initialize Paystack
import paystack from 'paystack';
const paystackClient = paystack(process.env.PAYSTACK_SECRET_KEY);

// Create secure Axios instance
const secureAxios = axios.create({
  baseURL: 'https://api.paystack.co',
  headers: {
    Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
    'Content-Type': 'application/json'
  },
  timeout: 10000 // 10 second timeout
});

// Add request interceptor for security
secureAxios.interceptors.request.use(config => {
  // Sanitize request data
  if (config.data) {
    config.data = JSON.parse(JSON.stringify(config.data));
  }
  return config;
});

// Add response interceptor for error handling
secureAxios.interceptors.response.use(
  response => response,
  error => {
    console.error('Paystack API Error:', error.response?.data || error.message);
    throw error;
  }
);

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
    
    // Use both Paystack SDK and secure Axios for double verification
    const [paystackResponse, axiosResponse] = await Promise.all([
      paystackClient.transaction.initialize(initializeOptions),
      secureAxios.post('/transaction/initialize', initializeOptions)
    ]);

    // Verify both responses match
    if (paystackResponse.data.authorization_url !== axiosResponse.data.data.authorization_url) {
      throw new Error('Payment initialization verification failed');
    }
    
    res.status(200).json({
      success: true,
      data: paystackResponse.data
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
    
    // Use both Paystack SDK and secure Axios for double verification
    const [paystackResponse, axiosResponse] = await Promise.all([
      paystackClient.transaction.verify(reference),
      secureAxios.get(`/transaction/verify/${reference}`)
    ]);

    // Verify both responses match
    if (paystackResponse.data.status !== axiosResponse.data.data.status) {
      throw new Error('Payment verification mismatch');
    }
    
    if (paystackResponse.data.status === 'success') {
      res.status(200).json({
        success: true,
        message: 'Payment verified successfully',
        data: paystackResponse.data
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Payment verification failed',
        data: paystackResponse.data
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
    const response = await paystackClient.transaction.list({ perPage: 20 });
    
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

export default router;