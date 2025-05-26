import { createClient } from 'redis';
import { promisify } from 'util';

class SocketMonitor {
  constructor() {
    this.metrics = {
      connections: new Map(),
      events: new Map(),
      errors: new Map(),
      latency: new Map()
    };

    // Initialize Redis client for distributed metrics
    if (process.env.REDIS_URL) {
      this.redis = createClient({
        url: process.env.REDIS_URL
      });
      this.redis.on('error', (err) => console.error('Redis error:', err));
    }

    // Bind methods
    this.trackConnection = this.trackConnection.bind(this);
    this.trackDisconnection = this.trackDisconnection.bind(this);
    this.trackEvent = this.trackEvent.bind(this);
    this.trackError = this.trackError.bind(this);
    this.trackLatency = this.trackLatency.bind(this);
    this.getMetrics = this.getMetrics.bind(this);
  }

  /**
   * Track new socket connection
   * @param {string} socketId - Socket identifier
   * @param {string} userId - User identifier
   */
  trackConnection(socketId, userId) {
    const timestamp = new Date();
    this.metrics.connections.set(socketId, {
      userId,
      connectedAt: timestamp,
      events: 0,
      errors: 0
    });

    // Update Redis if available
    if (this.redis) {
      this.redis.hSet('socket:connections', socketId, JSON.stringify({
        userId,
        connectedAt: timestamp.toISOString()
      }));
    }
  }

  /**
   * Track socket disconnection
   * @param {string} socketId - Socket identifier
   */
  trackDisconnection(socketId) {
    const connection = this.metrics.connections.get(socketId);
    if (connection) {
      const duration = new Date() - connection.connectedAt;
      this.metrics.connections.delete(socketId);

      // Update Redis if available
      if (this.redis) {
        this.redis.hDel('socket:connections', socketId);
        this.redis.hSet('socket:disconnections', socketId, JSON.stringify({
          userId: connection.userId,
          duration,
          events: connection.events,
          errors: connection.errors
        }));
      }
    }
  }

  /**
   * Track socket event
   * @param {string} eventName - Name of the event
   * @param {string} socketId - Socket identifier
   */
  trackEvent(eventName, socketId) {
    // Update event counts
    const eventCount = this.metrics.events.get(eventName) || 0;
    this.metrics.events.set(eventName, eventCount + 1);

    // Update connection event count
    const connection = this.metrics.connections.get(socketId);
    if (connection) {
      connection.events += 1;
      this.metrics.connections.set(socketId, connection);
    }

    // Update Redis if available
    if (this.redis) {
      this.redis.hIncrBy('socket:events', eventName, 1);
    }
  }

  /**
   * Track socket error
   * @param {string} errorType - Type of error
   * @param {string} socketId - Socket identifier
   * @param {Error} error - Error object
   */
  trackError(errorType, socketId, error) {
    // Update error counts
    const errorCount = this.metrics.errors.get(errorType) || 0;
    this.metrics.errors.set(errorType, errorCount + 1);

    // Update connection error count
    const connection = this.metrics.connections.get(socketId);
    if (connection) {
      connection.errors += 1;
      this.metrics.connections.set(socketId, connection);
    }

    // Update Redis if available
    if (this.redis) {
      this.redis.hIncrBy('socket:errors', errorType, 1);
      this.redis.hSet('socket:error:last', errorType, JSON.stringify({
        timestamp: new Date().toISOString(),
        socketId,
        error: error.message
      }));
    }
  }

  /**
   * Track event latency
   * @param {string} eventName - Name of the event
   * @param {number} latency - Latency in milliseconds
   */
  trackLatency(eventName, latency) {
    const latencyData = this.metrics.latency.get(eventName) || {
      count: 0,
      total: 0,
      min: Infinity,
      max: -Infinity
    };

    latencyData.count += 1;
    latencyData.total += latency;
    latencyData.min = Math.min(latencyData.min, latency);
    latencyData.max = Math.max(latencyData.max, latency);

    this.metrics.latency.set(eventName, latencyData);

    // Update Redis if available
    if (this.redis) {
      this.redis.hSet('socket:latency', eventName, JSON.stringify(latencyData));
    }
  }

  /**
   * Get current metrics
   * @returns {Object} Metrics object
   */
  async getMetrics() {
    const metrics = {
      activeConnections: this.metrics.connections.size,
      events: Object.fromEntries(this.metrics.events),
      errors: Object.fromEntries(this.metrics.errors),
      latency: Object.fromEntries(this.metrics.latency)
    };

    // Merge with Redis metrics if available
    if (this.redis) {
      try {
        const [redisEvents, redisErrors, redisLatency] = await Promise.all([
          promisify(this.redis.hGetAll).bind(this.redis)('socket:events'),
          promisify(this.redis.hGetAll).bind(this.redis)('socket:errors'),
          promisify(this.redis.hGetAll).bind(this.redis)('socket:latency')
        ]);

        // Merge metrics from all instances
        metrics.distributed = {
          events: redisEvents,
          errors: redisErrors,
          latency: Object.entries(redisLatency).reduce((acc, [key, value]) => {
            acc[key] = JSON.parse(value);
            return acc;
          }, {})
        };
      } catch (error) {
        console.error('Error fetching distributed metrics:', error);
      }
    }

    return metrics;
  }

  /**
   * Reset metrics
   */
  async resetMetrics() {
    this.metrics.events.clear();
    this.metrics.errors.clear();
    this.metrics.latency.clear();

    // Reset Redis metrics if available
    if (this.redis) {
      try {
        await Promise.all([
          this.redis.del('socket:events'),
          this.redis.del('socket:errors'),
          this.redis.del('socket:latency')
        ]);
      } catch (error) {
        console.error('Error resetting distributed metrics:', error);
      }
    }
  }
}

export default new SocketMonitor();