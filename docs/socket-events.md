# Socket.IO Event Documentation

This document describes all available WebSocket events in the Shopify Server application.

## Authentication

All Socket.IO connections require authentication using a JWT token.

```javascript
// Client-side connection with auth token
const socket = io('http://localhost:10000', {
  auth: {
    token: 'your-jwt-token'
  }
});
```

## Available Events

### Order Events

#### `order:subscribe`
Subscribe to real-time updates for a specific order.

```javascript
// Client sends
socket.emit('order:subscribe', { orderId: 'order-123' });

// Server responds with
socket.on('order:updated', (data) => {
  console.log('Order status:', data.status);
});
```

Payload:
```typescript
{
  orderId: string;
}
```

### Cart Events

#### `cart:update`
Update cart contents and notify other user sessions.

```javascript
// Client sends
socket.emit('cart:update', {
  userId: 'user-123',
  items: [
    { productId: 'prod-1', quantity: 2, price: 29.99 }
  ],
  total: 59.98
});

// Other sessions receive
socket.on('cart:updated', (cartData) => {
  console.log('Cart updated:', cartData);
});
```

#### `cart:stockWarning`
Receive warnings about low stock for items in cart.

```javascript
socket.on('cart:stockWarning', (data) => {
  console.log(`Product ${data.productId} has only ${data.availableStock} items left`);
});
```

### Product Events

#### `product:watch`
Subscribe to stock updates for a specific product.

```javascript
// Client sends
socket.emit('product:watch', 'product-123');

// Receive stock updates
socket.on('product:stockUpdate', (data) => {
  console.log(`New stock level: ${data.newStock}`);
});
```

## Error Handling

The server emits error events when operations fail:

```javascript
socket.on('error', (error) => {
  console.error('Socket error:', error.message);
});
```

## Rate Limiting

Socket events are rate-limited to prevent abuse:
- 10 events per second per connection
- Exceeding the limit will result in an error event

## Best Practices

1. **Connection Management**
   - Always provide an authentication token
   - Handle reconnection scenarios
   - Clean up subscriptions on disconnect

2. **Error Handling**
   - Listen for error events
   - Implement exponential backoff for reconnections
   - Validate event payloads before sending

3. **Performance**
   - Subscribe only to necessary events
   - Unsubscribe when data is no longer needed
   - Batch updates when possible

## Example Implementation

```javascript
// Complete client implementation example
const socket = io('http://localhost:10000', {
  auth: { token: 'jwt-token' },
  reconnection: true,
  reconnectionDelay: 1000,
  reconnectionDelayMax: 5000,
  reconnectionAttempts: 5
});

// Connection handling
socket.on('connect', () => {
  console.log('Connected to server');
});

socket.on('disconnect', (reason) => {
  console.log('Disconnected:', reason);
});

// Error handling
socket.on('connect_error', (error) => {
  console.error('Connection error:', error.message);
});

socket.on('error', (error) => {
  console.error('Socket error:', error.message);
});

// Event handling
socket.emit('order:subscribe', { orderId: 'order-123' });

socket.on('order:updated', (data) => {
  console.log('Order updated:', data);
});

// Cleanup on component unmount
return () => {
  socket.off('order:updated');
  socket.disconnect();
};
```