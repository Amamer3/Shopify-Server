/**
 * Script to create the first superadmin user directly in Firebase
 * 
 * Usage: 
 * 1. Set the email and password in this file
 * 2. Run with: node scripts/create-superadmin.js
 */

require('dotenv').config();
const { auth, db } = require('../config/firebase');

// Get superadmin credentials from environment variables or use defaults
const superadminEmail = process.env.SUPERADMIN_EMAIL || 'superadmin@shopify.com';
const superadminPassword = process.env.SUPERADMIN_PASSWORD;

// Check if password is provided
if (!superadminPassword) {
  console.error('Error: SUPERADMIN_PASSWORD environment variable is required');
  console.error('Please set it in your .env file or provide it as an environment variable');
  process.exit(1);
}

async function createSuperadmin() {
  try {
    console.log('Creating superadmin user...');
    
    // Create user in Firebase Authentication
    const userRecord = await auth.createUser({
      email: superadminEmail,
      password: superadminPassword,
      displayName: 'Super Admin',
      emailVerified: true
    });
    
    console.log('Superadmin created in Firebase Authentication');
    console.log('UID:', userRecord.uid);
    
    // Store superadmin data in Firestore
    await db.collection('users').doc(userRecord.uid).set({
      uid: userRecord.uid,
      email: superadminEmail,
      role: 'superadmin',
      createdAt: new Date().toISOString(),
      emailVerified: true,
      isFirstSuperadmin: true // Flag to identify this as the first superadmin
    });
    
    console.log('Superadmin data stored in Firestore');
    console.log('Superadmin creation completed successfully!');
    console.log('\nLogin credentials:');
    console.log('Email:', superadminEmail);
    console.log('Password:', superadminPassword);
    console.log('\nIMPORTANT: Change this password immediately after first login!');
  } catch (error) {
    console.error('Error creating superadmin:', error);
    
    // Check if user already exists
    if (error.code === 'auth/email-already-exists') {
      console.log('\nA user with this email already exists.');
      console.log('If you need to reset the superadmin, first delete the user from Firebase Authentication and Firestore.');
    }
  }
}

// Execute the function
createSuperadmin();