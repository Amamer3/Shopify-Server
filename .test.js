import request from 'supertest';
import app from './server';

// Example test suite
describe('GET /api/status', () => {
  it('should return operational status', async () => {
    const res = await request(app)
      .get('/api/status')
      .expect('Content-Type', /json/)
      .expect(200);

    expect(res.body).toHaveProperty('status', 'operational');
  });
});

describe('Orders API', () => {
  it('should create a new order', async () => {
    const response = await request(app)
      .post('/api/orders')
      .send({ /* order data */ });
    expect(response.statusCode).toBe(201);
    expect(response.body).toHaveProperty('orderId');
  });
});