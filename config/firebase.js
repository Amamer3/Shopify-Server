const admin = require('firebase-admin');
const dotenv = require('dotenv');

dotenv.config();

// Firebase configuration object from environment variables
const firebaseConfig = {

};

// Initialize Firebase Admin SDK
let firebaseApp;
try {
  // Check if Firebase is already initialized
  if (!admin.apps.length) {
    firebaseApp = admin.initializeApp({
      credential: admin.credential.cert(firebaseConfig)
    });
  } else {
    firebaseApp = admin.app();
  }
  console.log('Firebase Admin SDK initialized successfully');
} catch (error) {
  console.error('Error initializing Firebase Admin SDK:', error);
}

// Export Firebase services
module.exports = {
  admin,
  db: admin.firestore(),
  auth: admin.auth(),
  storage: admin.storage()
};