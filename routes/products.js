import express from 'express';
import { body, query } from 'express-validator';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
const router = express.Router();

// Import Firebase config
import { db, storage } from '../config/firebase.js';

// Import middleware
import { validateRequest } from '../middleware/errorHandler.js';
import { protect, authorize } from '../middleware/auth.js';

// Configure multer for image upload
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 5 // Max 5 files
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// Helper function to upload image to Firebase Storage
async function uploadImage(file) {
  const filename = `${uuidv4()}-${file.originalname}`;
  const fileRef = storage.ref(`products/${filename}`);
  
  await fileRef.put(file.buffer, {
    contentType: file.mimetype
  });
  
  return await fileRef.getDownloadURL();
}

/**
 * @route   GET /api/products
 * @desc    Get all products
 * @access  Public
 */
router.get('/', [
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('category').optional().isString(),
  query('minPrice').optional().isFloat({ min: 0 }).toFloat(),
  query('maxPrice').optional().isFloat({ min: 0 }).toFloat(),
  query('search').optional().isString(),
  query('sortBy').optional().isIn(['name', 'price', 'createdAt']),
  query('sortOrder').optional().isIn(['asc', 'desc']),
  query('inStock').optional().isBoolean().toBoolean()
], validateRequest, async (req, res, next) => {
  try {
    const {
      page = 1,
      limit = 10,
      category,
      minPrice,
      maxPrice,
      search,
      sortBy = 'createdAt',
      sortOrder = 'desc',
      inStock
    } = req.query;

    let query = db.collection('products');

    // Apply filters
    if (category) {
      query = query.where('category', '==', category);
    }
    if (typeof inStock === 'boolean') {
      query = query.where('stockQuantity', inStock ? '>' : '==', 0);
    }
    if (minPrice !== undefined) {
      query = query.where('price', '>=', minPrice);
    }
    if (maxPrice !== undefined) {
      query = query.where('price', '<=', maxPrice);
    }

    // Apply sorting
    query = query.orderBy(sortBy, sortOrder);

    // Get total count for pagination
    const totalSnapshot = await query.count().get();
    const total = totalSnapshot.data().count;

    // Apply pagination
    const startAt = (page - 1) * limit;
    query = query.offset(startAt).limit(limit);

    const productsSnapshot = await query.get();
    const products = [];

    productsSnapshot.forEach(doc => {
      const product = {
        id: doc.id,
        ...doc.data()
      };

      // Filter by search term if provided
      if (search) {
        const searchLower = search.toLowerCase();
        const matchesSearch = 
          product.name.toLowerCase().includes(searchLower) ||
          product.description.toLowerCase().includes(searchLower);

        if (matchesSearch) {
          products.push(product);
        }
      } else {
        products.push(product);
      }
    });

    res.status(200).json({
      success: true,
      data: {
        products,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalProducts: total,
          hasNextPage: startAt + limit < total,
          hasPrevPage: page > 1
        }
      }
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
  upload.array('images', 5),
  body('name').notEmpty().withMessage('Product name is required'),
  body('description').notEmpty().withMessage('Description is required'),
  body('price').isNumeric().withMessage('Price must be a number'),
  body('category').notEmpty().withMessage('Category is required'),
  body('stockQuantity').isInt({ min: 0 }).withMessage('Stock quantity must be a positive integer'),
  body('variants').optional().isArray().withMessage('Variants must be an array'),
  body('variants.*.name').optional().notEmpty().withMessage('Variant name is required'),
  body('variants.*.price').optional().isNumeric().withMessage('Variant price must be a number'),
  body('variants.*.stockQuantity').optional().isInt({ min: 0 }).withMessage('Variant stock quantity must be a positive integer'),
  body('tags').optional().isArray().withMessage('Tags must be an array'),
  body('featured').optional().isBoolean().withMessage('Featured must be a boolean')
], validateRequest, async (req, res, next) => {
  try {
    const { 
      name, 
      description, 
      price, 
      category, 
      stockQuantity,
      variants = [],
      tags = [],
      featured = false
    } = req.body;

    // Upload images to Firebase Storage
    const imageUrls = [];
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        const imageUrl = await uploadImage(file);
        imageUrls.push(imageUrl);
      }
    }

    // Process variants
    const processedVariants = variants.map(variant => ({
      ...variant,
      price: Number(variant.price),
      stockQuantity: Number(variant.stockQuantity),
      sku: `${name.substring(0, 3).toUpperCase()}-${variant.name.substring(0, 2).toUpperCase()}-${uuidv4().substring(0, 6)}`
    }));

    // Create product in Firestore
    const productRef = await db.collection('products').add({
      name,
      description,
      price: Number(price),
      category,
      images: imageUrls,
      stockQuantity: Number(stockQuantity),
      variants: processedVariants,
      tags,
      featured,
      sku: `${name.substring(0, 3).toUpperCase()}-${uuidv4().substring(0, 6)}`,
      createdAt: new Date().toISOString(),
      createdBy: req.user.uid,
      updatedAt: new Date().toISOString()
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

/**
 * @route   POST /api/products/bulk
 * @desc    Perform bulk operations on products
 * @access  Private (Admin)
 */
router.post('/bulk', [
  protect,
  authorize('admin'),
  body('action').isIn(['delete', 'update', 'updateStatus']).withMessage('Invalid action'),
  body('productIds').isArray().withMessage('Product IDs must be an array'),
  body('data').optional().isObject().withMessage('Update data must be an object')
], validateRequest, async (req, res, next) => {
  try {
    const { action, productIds, data } = req.body;
    const batch = db.batch();

    // Verify all products exist
    const products = await Promise.all(
      productIds.map(id => db.collection('products').doc(id).get())
    );

    const notFound = products.filter(doc => !doc.exists).map(doc => doc.id);
    if (notFound.length > 0) {
      return res.status(404).json({
        success: false,
        message: `Products not found: ${notFound.join(', ')}`
      });
    }

    switch (action) {
      case 'delete':
        productIds.forEach(id => {
          const ref = db.collection('products').doc(id);
          batch.delete(ref);
        });
        break;

      case 'update':
        if (!data) {
          return res.status(400).json({
            success: false,
            message: 'Update data is required'
          });
        }
        productIds.forEach(id => {
          const ref = db.collection('products').doc(id);
          batch.update(ref, {
            ...data,
            updatedAt: new Date().toISOString(),
            updatedBy: req.user.uid
          });
        });
        break;

      case 'updateStatus':
        if (!data || !data.status) {
          return res.status(400).json({
            success: false,
            message: 'Status is required'
          });
        }
        productIds.forEach(id => {
          const ref = db.collection('products').doc(id);
          batch.update(ref, {
            status: data.status,
            updatedAt: new Date().toISOString(),
            updatedBy: req.user.uid
          });
        });
        break;
    }

    await batch.commit();

    res.status(200).json({
      success: true,
      message: `Bulk ${action} completed successfully`,
      affectedProducts: productIds.length
    });
  } catch (error) {
    console.error('Bulk operation error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/products/:id/variants
 * @desc    Add a variant to a product
 * @access  Private (Admin, Manager)
 */
router.post('/:id/variants', [
  protect,
  authorize('admin', 'manager'),
  body('name').notEmpty().withMessage('Variant name is required'),
  body('price').isNumeric().withMessage('Variant price must be a number'),
  body('stockQuantity').isInt({ min: 0 }).withMessage('Stock quantity must be a positive integer')
], validateRequest, async (req, res, next) => {
  try {
    const productDoc = await db.collection('products').doc(req.params.id).get();
    
    if (!productDoc.exists) {
      return res.status(404).json({ message: 'Product not found' });
    }

    const { name, price, stockQuantity, ...attributes } = req.body;
    const variant = {
      name,
      price: Number(price),
      stockQuantity: Number(stockQuantity),
      sku: `${productDoc.data().name.substring(0, 3).toUpperCase()}-${name.substring(0, 2).toUpperCase()}-${uuidv4().substring(0, 6)}`,
      attributes,
      createdAt: new Date().toISOString()
    };

    const currentVariants = productDoc.data().variants || [];
    await db.collection('products').doc(req.params.id).update({
      variants: [...currentVariants, variant],
      updatedAt: new Date().toISOString(),
      updatedBy: req.user.uid
    });

    res.status(201).json({
      success: true,
      data: variant
    });
  } catch (error) {
    console.error('Add variant error:', error);
    next(error);
  }
});

/**
 * @route   PUT /api/products/:id/variants/:variantId
 * @desc    Update a product variant
 * @access  Private (Admin, Manager)
 */
router.put('/:id/variants/:variantId', [
  protect,
  authorize('admin', 'manager'),
  body('price').optional().isNumeric().withMessage('Price must be a number'),
  body('stockQuantity').optional().isInt({ min: 0 }).withMessage('Stock quantity must be a positive integer')
], validateRequest, async (req, res, next) => {
  try {
    const productDoc = await db.collection('products').doc(req.params.id).get();
    
    if (!productDoc.exists) {
      return res.status(404).json({ message: 'Product not found' });
    }

    const currentVariants = productDoc.data().variants || [];
    const variantIndex = currentVariants.findIndex(v => v.sku === req.params.variantId);

    if (variantIndex === -1) {
      return res.status(404).json({ message: 'Variant not found' });
    }

    const updatedVariant = {
      ...currentVariants[variantIndex],
      ...req.body,
      updatedAt: new Date().toISOString()
    };

    currentVariants[variantIndex] = updatedVariant;

    await db.collection('products').doc(req.params.id).update({
      variants: currentVariants,
      updatedAt: new Date().toISOString(),
      updatedBy: req.user.uid
    });

    res.status(200).json({
      success: true,
      data: updatedVariant
    });
  } catch (error) {
    console.error('Update variant error:', error);
    next(error);
  }
});

/**
 * @route   DELETE /api/products/:id/variants/:variantId
 * @desc    Delete a product variant
 * @access  Private (Admin, Manager)
 */
router.delete('/:id/variants/:variantId', protect, authorize('admin', 'manager'), async (req, res, next) => {
  try {
    const productDoc = await db.collection('products').doc(req.params.id).get();
    
    if (!productDoc.exists) {
      return res.status(404).json({ message: 'Product not found' });
    }

    const currentVariants = productDoc.data().variants || [];
    const updatedVariants = currentVariants.filter(v => v.sku !== req.params.variantId);

    if (currentVariants.length === updatedVariants.length) {
      return res.status(404).json({ message: 'Variant not found' });
    }

    await db.collection('products').doc(req.params.id).update({
      variants: updatedVariants,
      updatedAt: new Date().toISOString(),
      updatedBy: req.user.uid
    });

    res.status(200).json({
      success: true,
      message: 'Variant deleted successfully'
    });
  } catch (error) {
    console.error('Delete variant error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/products/categories
 * @desc    Get list of unique product categories
 * @access  Public
 */
router.get('/categories', async (req, res, next) => {
  try {
    const productsSnapshot = await db.collection('products').get();
    const categories = new Set();

    productsSnapshot.forEach(doc => {
      const category = doc.data().category;
      if (category) {
        categories.add(category);
      }
    });

    res.status(200).json({
      success: true,
      data: Array.from(categories).sort()
    });
  } catch (error) {
    console.error('Get categories error:', error);
    next(error);
  }
});

export default router;