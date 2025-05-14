const express = require('express');
const { body } = require('express-validator');
const router = express.Router();

// Import Firebase config
const { db } = require('../config/firebase');

// Import middleware
const { validateRequest } = require('../middleware/errorHandler');
const { protect, authorize } = require('../middleware/auth');

/**
 * @route   GET /api/categories
 * @desc    Get all categories
 * @access  Public
 */
router.get('/', async (req, res, next) => {
  try {
    const categoriesSnapshot = await db.collection('categories').get();
    const categories = [];
    
    categoriesSnapshot.forEach(doc => {
      categories.push({
        id: doc.id,
        ...doc.data()
      });
    });

    res.status(200).json({
      success: true,
      count: categories.length,
      data: categories
    });
  } catch (error) {
    console.error('Get categories error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/categories/:id
 * @desc    Get single category
 * @access  Public
 */
router.get('/:id', async (req, res, next) => {
  try {
    const categoryDoc = await db.collection('categories').doc(req.params.id).get();
    
    if (!categoryDoc.exists) {
      return res.status(404).json({ message: 'Category not found' });
    }

    // Get count of products in this category
    const productsSnapshot = await db.collection('products')
      .where('category', '==', req.params.id)
      .get();

    res.status(200).json({
      success: true,
      data: {
        id: categoryDoc.id,
        ...categoryDoc.data(),
        productCount: productsSnapshot.size
      }
    });
  } catch (error) {
    console.error('Get category error:', error);
    next(error);
  }
});

/**
 * @route   POST /api/categories
 * @desc    Create a new category
 * @access  Private (Admin, Manager)
 */
router.post('/', [
  protect,
  authorize('admin', 'manager'),
  body('name').notEmpty().withMessage('Category name is required'),
  body('description').optional(),
  body('slug').notEmpty().withMessage('Slug is required')
], validateRequest, async (req, res, next) => {
  try {
    const { name, description, slug } = req.body;

    // Check if slug already exists
    const existingCategorySnapshot = await db.collection('categories')
      .where('slug', '==', slug)
      .get();

    if (!existingCategorySnapshot.empty) {
      return res.status(400).json({ message: 'Slug already exists' });
    }

    // Create new category
    const categoryRef = db.collection('categories').doc();
    const categoryData = {
      name,
      description: description || '',
      slug,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    await categoryRef.set(categoryData);

    res.status(201).json({
      success: true,
      data: {
        id: categoryRef.id,
        ...categoryData
      }
    });
  } catch (error) {
    console.error('Create category error:', error);
    next(error);
  }
});

/**
 * @route   PUT /api/categories/:id
 * @desc    Update category
 * @access  Private (Admin, Manager)
 */
router.put('/:id', [
  protect,
  authorize('admin', 'manager'),
  body('name').optional(),
  body('description').optional(),
  body('slug').optional()
], validateRequest, async (req, res, next) => {
  try {
    const categoryDoc = await db.collection('categories').doc(req.params.id).get();
    
    if (!categoryDoc.exists) {
      return res.status(404).json({ message: 'Category not found' });
    }

    const { name, description, slug } = req.body;
    const updateData = {};

    // Only update fields that are provided
    if (name) updateData.name = name;
    if (description !== undefined) updateData.description = description;
    
    // If slug is being updated, check if it already exists
    if (slug && slug !== categoryDoc.data().slug) {
      const existingCategorySnapshot = await db.collection('categories')
        .where('slug', '==', slug)
        .get();

      if (!existingCategorySnapshot.empty) {
        return res.status(400).json({ message: 'Slug already exists' });
      }
      
      updateData.slug = slug;
    }

    updateData.updatedAt = new Date().toISOString();

    // Update category
    await db.collection('categories').doc(req.params.id).update(updateData);

    // Get updated category
    const updatedCategoryDoc = await db.collection('categories').doc(req.params.id).get();

    res.status(200).json({
      success: true,
      data: {
        id: updatedCategoryDoc.id,
        ...updatedCategoryDoc.data()
      }
    });
  } catch (error) {
    console.error('Update category error:', error);
    next(error);
  }
});

/**
 * @route   DELETE /api/categories/:id
 * @desc    Delete category
 * @access  Private (Admin)
 */
router.delete('/:id', [
  protect,
  authorize('admin')
], async (req, res, next) => {
  try {
    const categoryDoc = await db.collection('categories').doc(req.params.id).get();
    
    if (!categoryDoc.exists) {
      return res.status(404).json({ message: 'Category not found' });
    }

    // Check if category has products
    const productsSnapshot = await db.collection('products')
      .where('category', '==', req.params.id)
      .get();

    if (!productsSnapshot.empty) {
      return res.status(400).json({ 
        message: 'Cannot delete category with products. Remove or reassign products first.',
        productCount: productsSnapshot.size
      });
    }

    // Delete category
    await db.collection('categories').doc(req.params.id).delete();

    res.status(200).json({
      success: true,
      message: 'Category deleted successfully'
    });
  } catch (error) {
    console.error('Delete category error:', error);
    next(error);
  }
});

/**
 * @route   GET /api/categories/:id/products
 * @desc    Get all products in a category
 * @access  Public
 */
router.get('/:id/products', async (req, res, next) => {
  try {
    const categoryDoc = await db.collection('categories').doc(req.params.id).get();
    
    if (!categoryDoc.exists) {
      return res.status(404).json({ message: 'Category not found' });
    }

    // Get products in this category
    const productsSnapshot = await db.collection('products')
      .where('category', '==', req.params.id)
      .get();

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
      category: {
        id: categoryDoc.id,
        ...categoryDoc.data()
      },
      data: products
    });
  } catch (error) {
    console.error('Get category products error:', error);
    next(error);
  }
});

module.exports = router;