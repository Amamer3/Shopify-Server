# Shopify Server Backend

A Node.js backend server for Shopify with Express.js and Firebase integration. This server provides authentication, product management, order processing, user management, analytics, and inventory control functionalities.

## Features

- **Authentication & Authorization**
  - Firebase Authentication integration
  - JWT middleware for protected routes
  - Role-based access control (Admin, Superadmin)
  - Session management

- **API Endpoints**
  - Products management (`/api/products`)
  - Orders handling (`/api/orders`)
  - User management (`/api/users`)
  - Analytics data (`/api/analytics`)
  - Inventory control (`/api/inventory`)
  - User profiles (`/api/profile`)
  - Wishlist management (`/api/wishlist`)

- **Firebase Integration**
  - Firestore for data storage
  - Firebase Storage for image uploads
  - Real-time updates for order status

- **Security Features**
  - Request validation
  - Rate limiting
  - CORS configuration
  - Error handling middleware
  - Input sanitization

## Prerequisites

- Node.js (v14 or higher)
- Firebase account with a project set up
- Firebase Admin SDK credentials

## Installation

1. Clone the repository

```bash
git clone <repository-url>
cd Shopify-Server
```

2. Install dependencies

```bash
npm install
```

3. Configure environment variables

Create a `.env` file in the root directory and add your Firebase configuration and other environment variables:

```env
# Environment Variables
PORT=5000
NODE_ENV=development

# Firebase Configuration
FIREBASE_TYPE=service_account
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_PRIVATE_KEY_ID=your-private-key-id
FIREBASE_PRIVATE_KEY=your-private-key
FIREBASE_CLIENT_EMAIL=your-client-email
FIREBASE_CLIENT_ID=your-client-id
FIREBASE_AUTH_URI=https://accounts.google.com/o/oauth2/auth
FIREBASE_TOKEN_URI=https://oauth2.googleapis.com/token
FIREBASE_AUTH_PROVIDER_X509_CERT_URL=https://www.googleapis.com/oauth2/v1/certs
FIREBASE_CLIENT_X509_CERT_URL=your-cert-url

# JWT Secret
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRES_IN=1d
```

## Usage

1. Create the first superadmin (initial setup)

```bash
node scripts/create-superadmin.js
```

2. Start the development server

```bash
npm run dev
```

3. Start the production server

```bash
npm start
```

## API Documentation

### Profile Endpoints

#### Get User Profile
- **URL**: `/api/profile`
- **Method**: `GET`
- **Auth**: Required
- **Description**: Get user's profile information including addresses and payment methods
- **Response**: User profile data with addresses and payment methods

#### Get User Orders
- **URL**: `/api/profile/orders`
- **Method**: `GET`
- **Auth**: Required
- **Description**: Get user's order history
- **Response**: List of user's orders

### Wishlist Endpoints

#### Add to Wishlist
- **URL**: `/api/wishlist`
- **Method**: `POST`
- **Auth**: Required
- **Body**: `{ "productId": "string" }`
- **Description**: Add a product to user's wishlist
- **Response**: Success message

#### Get Wishlist
- **URL**: `/api/wishlist`
- **Method**: `GET`
- **Auth**: Required
- **Description**: Get user's wishlist with product details
- **Response**: List of products in wishlist

#### Remove from Wishlist
- **URL**: `/api/wishlist/:productId`
- **Method**: `DELETE`
- **Auth**: Required
- **Description**: Remove a product from wishlist
- **Response**: Success message

#### Clear Wishlist
- **URL**: `/api/wishlist`
- **Method**: `DELETE`
- **Auth**: Required
- **Description**: Remove all products from wishlist
- **Response**: Success message

### Authentication

- `POST /api/auth/register` - Register a new user (requires firstName, lastName, email, password)
- `POST /api/auth/login` - Login user and return JWT token
- `POST /api/auth/register-admin` - Register a new admin (superadmin access only)
- `POST /api/auth/register-superadmin` - Register a new superadmin (superadmin access only)
- `POST /api/auth/forgot-password` - Send password reset email
- `POST /api/auth/reset-password/:token` - Reset user password with token
- `POST /api/auth/verify-email` - Verify user email address

### Products

- `GET /api/products` - Get all products
- `GET /api/products/:id` - Get single product
- `POST /api/products` - Create a new product (Admin, Superadmin)
- `PUT /api/products/:id` - Update product (Admin, Superadmin)
- `DELETE /api/products/:id` - Delete product (Admin, Superadmin)

### Categories

- `GET /api/categories` - Get all categories
- `GET /api/categories/:id` - Get single category
- `POST /api/categories` - Create a new category (Admin, Superadmin)
- `PUT /api/categories/:id` - Update category (Admin, Superadmin)
- `DELETE /api/categories/:id` - Delete category (Admin, Superadmin)
- `GET /api/categories/:id/products` - Get all products in a category

### Cart

- `GET /api/cart` - Get user's cart
- `POST /api/cart` - Add item to cart
- `PUT /api/cart/:productId` - Update cart item quantity
- `DELETE /api/cart/:productId` - Remove item from cart
- `DELETE /api/cart` - Clear cart

### Orders

- `GET /api/orders` - Get all orders (Admin, Superadmin)
- `GET /api/orders/my-orders` - Get orders for current user
- `GET /api/orders/:id` - Get single order
- `POST /api/orders` - Create a new order
- `PUT /api/orders/:id/status` - Update order status (Admin, Superadmin)
- `DELETE /api/orders/:id` - Cancel order (Admin, Superadmin or order owner)
- `GET /api/orders` - Get all orders (Superadmin, Admin)
- `GET /api/orders/my-orders` - Get orders for the current user
- `DELETE /api/orders/:id` - Delete an order (Superadmin, Admin)


### User Management

- `GET /api/users` - Get all users (Admin, Superadmin)
- `GET /api/users/:id` - Get single user (Admin, Superadmin or own profile)
- `PUT /api/users/:id` - Update user profile (Admin, Superadmin or own profile)
- `DELETE /api/users/:id` - Delete user (Admin, Superadmin)
### Users
- `GET /api/users` - Get all users (Superadmin, Admin)
- `GET /api/users/:id` - Get single user (Superadmin, Admin, or own profile)
- `PUT /api/users/:id` - Update user profile (Superadmin, Admin, or own profile)
- `DELETE /api/users/:id` - Delete a user (Superadmin, Admin)

### Profile Management

- `GET /api/profile` - Get user profile with addresses, payment methods, and recent orders
- `PUT /api/profile` - Update user profile
- `POST /api/profile/addresses` - Add a new address
- `PUT /api/profile/addresses/:id` - Update address
- `DELETE /api/profile/addresses/:id` - Delete address
- `POST /api/profile/payment-methods` - Add a new payment method
- `DELETE /api/profile/payment-methods/:id` - Delete payment method
- `GET /api/profile/orders` - Get user's order history with pagination

### Analytics (Superadmin, Admin)

- `GET /api/analytics/sales` - Get sales analytics by period (day, week, month, year)
- `GET /api/analytics/products` - Get product performance analytics
- `GET /api/analytics/customers` - Get customer analytics
- `GET /api/analytics/dashboard` - Get dashboard overview statistics
- `GET /api/analytics/sales` - Get sales analytics (Superadmin, Admin)
- `GET /api/analytics/inventory` - Get inventory analytics (Superadmin, Admin)
- `GET /api/analytics/users` - Get user analytics (Superadmin, Admin)

### Inventory Management

- `GET /api/inventory` - Get inventory status for all products (Superadmin, Admin)
- `GET /api/inventory/low-stock` - Get products with low stock (Superadmin, Admin)
- `PUT /api/inventory/:id` - Update product inventory (Superadmin,vAdmin)
- `POST /api/inventory/bulk-update` - Bulk update inventory (Superadmin, Admin)
- `POST /api/inventory/stock-alert` - Configure stock alert thresholds (Superadmin, Admin)

### Products

- `GET /api/products` - Get all products
- `GET /api/products/:id` - Get single product
- `POST /api/products` - Create a new product (Superadmin, Admin)
- `PUT /api/products/:id` - Update a product (Superadmin, Admin)
- `DELETE /api/products/:id` - Delete a product (Superadmin, Admin)

### Inventory

- `GET /api/inventory` - Get inventory status for all products
- `GET /api/inventory/low-stock` - Get products with low stock
- `PUT /api/inventory/:id` - Update product inventory (Superadmin, Admin)
- `POST /api/inventory/bulk-update` - Bulk update product inventory (Superadmin, Admin)
- `GET /api/inventory/history/:id` - Get inventory history for a product (Superadmin, Admin)

### Payments
- POST /api/payments/initialize - Initializes a payment transaction with Paystack
- GET /api/payments/verify/:reference - Verifies a payment transaction status
- POST /api/payments/webhook - Handles Paystack webhooks for real-time payment updates
- GET /api/payments/transactions - Retrieves a user's payment transaction history
- GET /api/payments/transactions/:id - Retrieves details of a specific payment transaction
- GET /api/payments/transactions/:id/verify - Verifies the status of a specific payment transaction

## License

ISC


### System Health & Monitoring

- `GET /health` - Get system health metrics (uptime, memory usage, CPU usage)
- `GET /api/status` - Get API operational status and service availability

Each request is automatically logged with:
- Request timestamp
- HTTP method and path
- Response status code
- Request duration
- User agent
- User ID (if authenticated)