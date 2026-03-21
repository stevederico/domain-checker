// ==== IMPORTS ====
import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { serveStatic } from '@hono/node-server/serve-static'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { secureHeaders } from 'hono/secure-headers'
import { cors } from 'hono/cors'
import Stripe from "stripe";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";

import { databaseManager } from "./adapters/manager.js";
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile, mkdir, stat, readFileSync, writeFileSync, statSync } from 'node:fs';
import { promisify } from 'node:util';
import dns from 'node:dns';
import net from 'node:net';

// ==== SERVER CONFIG ====
const port = parseInt(process.env.PORT || "8000");

// ==== CSRF PROTECTION ====
const csrfTokenStore = new Map(); // userID -> { token, timestamp }
const CSRF_TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours
const CSRF_MAX_ENTRIES = 50000; // LRU eviction threshold

/**
 * LRU eviction helper that removes oldest entries when over limit
 *
 * Prevents memory leaks in rate limiter and CSRF stores by removing oldest
 * entries based on timestamp when store exceeds maxEntries threshold.
 *
 * @param {Map} store - Map to evict entries from
 * @param {number} maxEntries - Maximum entries before eviction
 * @param {Function} getTimestamp - Function to extract timestamp from value
 * @returns {void}
 */
function evictOldestEntries(store, maxEntries, getTimestamp) {
  if (store.size <= maxEntries) return;

  // Convert to array and sort by timestamp
  const entries = Array.from(store.entries())
    .map(([key, value]) => ({ key, timestamp: getTimestamp(value) }))
    .sort((a, b) => a.timestamp - b.timestamp);

  // Remove oldest entries until under limit
  const toRemove = store.size - maxEntries;
  for (let i = 0; i < toRemove; i++) {
    store.delete(entries[i].key);
  }
}

/**
 * Generate cryptographically secure CSRF token
 *
 * Uses crypto.randomBytes to generate 64-character hex token.
 *
 * @returns {string} Hex-encoded CSRF token
 */
function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * CSRF protection middleware using timing-safe comparison
 *
 * Validates CSRF token from x-csrf-token header against stored token for userID.
 * Skips validation for GET requests and signup/signin routes. Uses timing-safe
 * comparison to prevent timing attacks. Enforces 24-hour token expiry.
 * Auto-regenerates token if missing (e.g., server restart) for authenticated users.
 *
 * @async
 * @param {Context} c - Hono context
 * @param {Function} next - Next middleware function
 * @returns {Promise<Response|void>} 403 error or continues to next middleware
 */
async function csrfProtection(c, next) {
  if (c.req.method === 'GET' || c.req.path === '/api/signup' || c.req.path === '/api/signin') {
    return next();
  }

  const csrfToken = c.req.header('x-csrf-token');
  const userID = c.get('userID'); // Set by authMiddleware

  if (!csrfToken || !userID) {
    logger.info('CSRF validation failed - missing token or userID', {
      hasToken: !!csrfToken,
      hasUserID: !!userID,
      path: redactPath(c.req.path)
    });
    return c.json({ error: 'Invalid CSRF token' }, 403);
  }

  let storedData = csrfTokenStore.get(userID);
  if (!storedData) {
    // Auto-regenerate token for authenticated users (e.g., after server restart)
    // Security: This block only runs if authMiddleware passed (JWT valid)
    const newToken = generateCSRFToken();
    storedData = { token: newToken, timestamp: Date.now() };
    csrfTokenStore.set(userID, storedData);

    setCookie(c, 'csrf_token', newToken, {
      httpOnly: false,
      secure: !isDevelopment,
      sameSite: 'Lax',
      path: '/',
      maxAge: CSRF_TOKEN_EXPIRY / 1000
    });

    logger.info('CSRF token auto-regenerated after store miss', { userID });
    await next();
    return;
  }

  // Use timing-safe comparison to prevent timing attacks
  const tokenBuffer = Buffer.from(csrfToken);
  const storedBuffer = Buffer.from(storedData.token);
  if (tokenBuffer.length !== storedBuffer.length || !crypto.timingSafeEqual(tokenBuffer, storedBuffer)) {
    logger.info('CSRF validation failed - token mismatch', {
      userID,
      path: redactPath(c.req.path)
    });
    return c.json({ error: 'Invalid CSRF token' }, 403);
  }

  // Check if token is expired
  if (Date.now() - storedData.timestamp > CSRF_TOKEN_EXPIRY) {
    csrfTokenStore.delete(userID);
    logger.info('CSRF validation failed - token expired', {
      userID,
      age: Math.floor((Date.now() - storedData.timestamp) / 1000) + 's'
    });
    return c.json({ error: 'CSRF token expired' }, 403);
  }

  logger.debug('CSRF validation passed', { userID });
  await next();
}

// Cleanup expired CSRF tokens every hour to prevent memory leak
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;

  for (const [userID, data] of csrfTokenStore.entries()) {
    if (now - data.timestamp > CSRF_TOKEN_EXPIRY) {
      csrfTokenStore.delete(userID);
      cleaned++;
    }
  }

  // LRU eviction if still over limit
  evictOldestEntries(csrfTokenStore, CSRF_MAX_ENTRIES, (data) => data.timestamp);

  if (cleaned > 0) {
    console.log(`[${new Date().toISOString()}] CSRF cleanup: removed ${cleaned} expired tokens`);
  }
}, 60 * 60 * 1000); // Run every hour

// ==== CONFIG & ENV ====
// Environment setup - MUST happen before config loading
if (!isProd()) {
  loadLocalENV();
} else {
  setInterval(async () => {
    console.log(`Hourly Completed at ${new Date().toLocaleTimeString()}`);
  }, 60 * 60 * 1000); // Every hour
}

/**
 * Resolve environment variable placeholders in configuration strings
 *
 * Replaces ${VAR_NAME} patterns with process.env values. Logs warning
 * and preserves placeholder if environment variable is undefined.
 *
 * @param {string} str - String with ${VAR_NAME} placeholders
 * @returns {string} String with placeholders replaced
 */
function resolveEnvironmentVariables(str) {
  if (typeof str !== 'string') return str;

  return str.replace(/\$\{([^}]+)\}/g, (match, varName) => {
    const envValue = process.env[varName];
    if (envValue === undefined) {
      console.warn(`Environment variable ${varName} is not defined, using placeholder: ${match}`);
      return match; // Return the placeholder if env var is not found
    }
    return envValue;
  });
}

// Load and process configuration
let config;
try {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const configPath = resolve(__dirname, './config.json');
  const configData = await promisify(readFile)(configPath);
  const rawConfig = JSON.parse(configData.toString());

  // Resolve environment variables in configuration
  config = {
    staticDir: rawConfig.staticDir || '../dist',
    database: {
      ...rawConfig.database,
      connectionString: resolveEnvironmentVariables(rawConfig.database.connectionString)
    }
  };
} catch (err) {
  console.error('Failed to load config:', err);
  config = {
    staticDir: '../dist',
    database: {
      db: "MyApp",
      dbType: "sqlite",
      connectionString: "./databases/MyApp.db"
    }
  };
}

const STRIPE_KEY = process.env.STRIPE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

/**
 * Validate required environment variables are set
 *
 * Checks for STRIPE_KEY, STRIPE_ENDPOINT_SECRET, JWT_SECRET, and any
 * unresolved ${VAR} references in database config. Logs warnings for
 * missing variables but does not exit the process.
 *
 * @returns {boolean} True if all required variables are present
 */
function validateEnvironmentVariables() {
  const missing = [];

  if (!STRIPE_KEY) missing.push('STRIPE_KEY');
  if (!process.env.STRIPE_ENDPOINT_SECRET) missing.push('STRIPE_ENDPOINT_SECRET');
  if (!JWT_SECRET) missing.push('JWT_SECRET');

  // Check for database environment variables that are referenced but not defined
  if (typeof config.database.connectionString === 'string') {
    const matches = config.database.connectionString.match(/\$\{([^}]+)\}/g);
    if (matches) {
      matches.forEach(match => {
        const varName = match.slice(2, -1); // Remove ${ and }
        if (!process.env[varName]) {
          missing.push(`${varName} (referenced in database config)`);
        }
      });
    }
  }

  if (missing.length > 0) {
    console.warn("⚠️  Missing environment variables (server will continue with limited functionality):");
    missing.forEach(varName => console.warn(`   - ${varName}`));
    console.warn("\n💡 For full functionality, set these environment variables:");
    console.warn("   - DATABASE_URL (general database connection)");
    console.warn("   - MONGODB_URL (MongoDB connection)");
    console.warn("   - POSTGRES_URL (PostgreSQL connection)");
    console.warn("   - STRIPE_KEY (Stripe payments)");
    console.warn("   - JWT_SECRET (authentication)");
    console.warn("\n🔄 Server continuing with fallback/default values...\n");

    // Don't exit - let the server continue with warnings
    return false;
  }

  return true;
}

const envValidationPassed = validateEnvironmentVariables();

if (envValidationPassed) {
  console.log('✅ Environment variables validated successfully');
}

console.log('Single-client backend initialized');

// Development mode check
const isDevelopment = process.env.NODE_ENV !== 'production';

// Structured logging system (no external dependencies)
const logger = {
  error: (message, meta = {}) => {
    const logEntry = {
      level: 'ERROR',
      timestamp: new Date().toISOString(),
      message,
      ...meta
    };
    console.error(isDevelopment ? JSON.stringify(logEntry, null, 2) : JSON.stringify(logEntry));
  },

  warn: (message, meta = {}) => {
    const logEntry = {
      level: 'WARN',
      timestamp: new Date().toISOString(),
      message,
      ...meta
    };
    console.warn(isDevelopment ? JSON.stringify(logEntry, null, 2) : JSON.stringify(logEntry));
  },

  info: (message, meta = {}) => {
    const logEntry = {
      level: 'INFO',
      timestamp: new Date().toISOString(),
      message,
      ...meta
    };
    console.log(isDevelopment ? JSON.stringify(logEntry, null, 2) : JSON.stringify(logEntry));
  },

  debug: (message, meta = {}) => {
    if (!isDevelopment) return;
    const logEntry = {
      level: 'DEBUG',
      timestamp: new Date().toISOString(),
      message,
      ...meta
    };
    console.log(JSON.stringify(logEntry, null, 2));
  }
};

/**
 * Redact domain query data from request paths
 *
 * Strips query parameters from /api/check paths to prevent domain names
 * from appearing in server logs. Other paths are returned unchanged.
 *
 * @param {string} path - Request path to redact
 * @returns {string} Redacted path
 */
function redactPath(path) {
  if (path.startsWith('/api/check')) return '/api/check';
  return path;
}

// Log server initialization
logger.info('Server initialization started', {
  environment: isDevelopment ? 'development' : 'production'
});

// ==== DATABASE CONFIG ====
// Single database configuration - no origin-based routing needed
const dbConfig = config.database;

// ==== SERVICES SETUP ====
// Stripe setup (only if key is available)
let stripe = null;
if (STRIPE_KEY) {
  stripe = new Stripe(STRIPE_KEY);
} else {
  console.warn('⚠️  STRIPE_KEY not set - Stripe functionality will be disabled');
}

// Single database config - always use the same one
const currentDbConfig = dbConfig;

// ==== HONO SETUP ====
const app = new Hono();

// Get __dirname for static file serving
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// CORS middleware (needed for development when frontend is on different port)
// Use CORS_ORIGINS env var in production, fallback to localhost for development
const corsOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:5173', 'http://localhost:8000', 'http://127.0.0.1:5173', 'http://127.0.0.1:8000'];

app.use('*', cors({
  origin: corsOrigins,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
  credentials: true
}));

// Apache Common Log Format middleware
app.use('*', async (c, next) => {
  const start = Date.now();
  await next();
  const timestamp = new Date().toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, '');
  const method = c.req.method;
  const url = c.req.path;
  const status = c.res.status;
  const duration = Date.now() - start;

  console.log(`[${timestamp}] "${method} ${redactPath(url)}" ${status} (${duration}ms)`);
});

// Security headers middleware
app.use('*', secureHeaders({
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "https://static.cloudflareinsights.com"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:"],
    fontSrc: ["'self'"],
    connectSrc: isDevelopment ? ["'self'", "http://localhost:8000"] : ["'self'", "https://cloudflareinsights.com"],
    frameAncestors: ["'none'"]
  },
  strictTransportSecurity: isDevelopment ? false : 'max-age=31536000; includeSubDomains; preload',
  xFrameOptions: 'DENY',
  xContentTypeOptions: 'nosniff',
  referrerPolicy: 'no-referrer',
  permissionsPolicy: {
    camera: [],
    microphone: [],
    geolocation: [],
    payment: []
  }
}));

// Request logging middleware (dev only)
app.use('*', async (c, next) => {
  if (isDevelopment) {
    const requestId = Math.random().toString(36).substr(2, 9);
    console.log(`[${new Date().toISOString()}] ${c.req.method} ${redactPath(c.req.path)} - ID: ${requestId}`);
  }
  await next();
});

const tokenExpirationDays = 30;

/**
 * Hash password using bcrypt with 10 salt rounds
 *
 * Generates salt and hashes password for secure storage. Uses bcrypt's
 * automatic salt generation.
 *
 * @async
 * @param {string} password - Plain text password to hash
 * @returns {Promise<string>} Bcrypt hashed password
 * @throws {Error} If bcrypt hashing fails
 */
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}

/**
 * Verify password against bcrypt hash using timing-safe comparison
 *
 * @async
 * @param {string} password - Plain text password to verify
 * @param {string} hash - Bcrypt hash to compare against
 * @returns {Promise<boolean>} True if password matches hash
 */
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

/**
 * Calculate JWT expiration timestamp
 *
 * @returns {number} Unix timestamp 30 days in the future
 */
function tokenExpireTimestamp(){
  return Math.floor(Date.now() / 1000) + tokenExpirationDays * 24 * 60 * 60; // 30 days from now
}

/**
 * Generate JWT token for user authentication
 *
 * Creates HS256-signed JWT with 30-day expiration. Requires JWT_SECRET
 * environment variable.
 *
 * @async
 * @param {string} userID - User ID to encode in token
 * @returns {Promise<string>} Signed JWT token
 * @throws {Error} If JWT_SECRET not configured or signing fails
 */
async function generateToken(userID) {
  try {
    if (!JWT_SECRET) {
      throw new Error("JWT_SECRET not configured - authentication disabled");
    }

    const exp = tokenExpireTimestamp();
    const payload = { userID, exp };

    return jwt.sign(payload, JWT_SECRET, {
      algorithm: 'HS256',
      header: { alg: "HS256", typ: "JWT" }
    });
  } catch (error) {
    logger.error('Token generation error', { error: error.message });
    throw error;
  }
}

/**
 * Authentication middleware using JWT from HttpOnly cookie
 *
 * Verifies JWT token from 'token' cookie. Sets userID in context on success,
 * normalized to string for consistent Map key usage across middleware (CSRF, sessions).
 * Returns 401 for missing, expired, or invalid tokens. Returns 503 if
 * JWT_SECRET not configured.
 *
 * @async
 * @param {Context} c - Hono context
 * @param {Function} next - Next middleware function
 * @returns {Promise<Response|void>} 401/503 error or continues to next middleware
 */
async function authMiddleware(c, next) {
  if (!JWT_SECRET) {
    return c.json({ error: "Authentication service unavailable" }, 503);
  }

  // Read token from HttpOnly cookie
  const token = getCookie(c, 'token');
  if (!token) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    // Normalize userID to string for consistent Map key usage (CSRF, sessions)
    const normalizedUserID = String(payload.userID);
    c.set('userID', normalizedUserID);
    await next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      logger.debug('Token expired');
      return c.json({ error: "Token expired" }, 401);
    }
    logger.error('Token verification error', { error: error.message });
    return c.json({ error: "Invalid token" }, 401);
  }
}

/**
 * Generate RFC 4122 compliant UUID v4
 *
 * Uses crypto.randomUUID() for cryptographically secure unique identifiers.
 *
 * @returns {string} UUID string
 */
function generateUUID() {
  return crypto.randomUUID();
}

/**
 * Escape HTML special characters to prevent XSS attacks
 *
 * Replaces &, <, >, ", ', / with HTML entities. Returns original value
 * if not a string.
 *
 * @param {string} text - Text to escape
 * @returns {string} HTML-escaped text
 */
const escapeHtml = (text) => {
  if (typeof text !== 'string') return text;
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
  };
  return text.replace(/[&<>"'/]/g, (char) => map[char]);
};

/**
 * Validate email address format and length
 *
 * RFC 5321 compliant validation with robust regex checking local part,
 * domain, and TLD. Max length 254 characters. Prevents consecutive dots
 * and leading/trailing hyphens.
 *
 * @param {string} email - Email address to validate
 * @returns {boolean} True if valid email format
 */
const validateEmail = (email) => {
  if (!email || typeof email !== 'string') return false;
  if (email.length > 254) return false; // RFC 5321

  // More robust email validation:
  // - Local part: letters, numbers, and common special chars (no consecutive dots)
  // - Domain: letters, numbers, hyphens (no consecutive dots or leading/trailing hyphens)
  // - TLD: 2-63 characters
  const emailRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]*[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,63}$/;
  return emailRegex.test(email);
};

/**
 * Validate password length within bcrypt limits
 *
 * Enforces 6-72 character range (bcrypt's maximum is 72 bytes).
 *
 * @param {string} password - Password to validate
 * @returns {boolean} True if valid password length
 */
const validatePassword = (password) => {
  if (!password || typeof password !== 'string') return false;
  if (password.length < 6 || password.length > 72) return false; // bcrypt limit
  return true;
};

/**
 * Validate name length and non-empty after trim
 *
 * Enforces 1-100 character range after trimming whitespace.
 *
 * @param {string} name - Name to validate
 * @returns {boolean} True if valid name
 */
const validateName = (name) => {
  if (!name || typeof name !== 'string') return false;
  if (name.trim().length === 0 || name.length > 100) return false;
  return true;
};

// ==== STRIPE WEBHOOK (raw body needed) ====
app.post("/api/payment", async (c) => {
  logger.info('Payment webhook received');

  const signature = c.req.header("stripe-signature");
  const rawBody = await c.req.arrayBuffer();
  const body = Buffer.from(rawBody);

  let event;
  try {
    event = await stripe.webhooks.constructEventAsync(body, signature, process.env.STRIPE_ENDPOINT_SECRET);
    logger.debug('Webhook event received', { type: event.type });
  } catch (e) {
    logger.error('Webhook signature verification failed', { error: e.message });
    return c.body(null, 400);
  }

  try {
    // Use the single database config for webhooks
    const webhookConfig = currentDbConfig;
    const { customer: stripeID, current_period_end, status } = event.data.object;

    // Validate required fields exist
    if (!stripeID) {
      logger.error('Webhook missing customer ID');
      return c.body(null, 400);
    }

    const customer = await stripe.customers.retrieve(stripeID);

    // Null check for customer email
    if (!customer || !customer.email) {
      logger.error('Webhook: Customer has no email', { stripeID });
      return c.body(null, 400);
    }

    const customerEmail = customer.email.toLowerCase();

    if (["customer.subscription.deleted", "customer.subscription.updated","customer.subscription.created"].includes(event.type)) {
      logger.info('Webhook processed', { type: event.type });
      const user = await databaseManager.findUser(webhookConfig.dbType, webhookConfig.db, webhookConfig.connectionString, { email: customerEmail });
      if (user) {
        await databaseManager.updateUser(webhookConfig.dbType, webhookConfig.db, webhookConfig.connectionString, { email: customerEmail }, {
          $set: { subscription: { stripeID, expires: current_period_end, status } }
        });
      } else {
        logger.warn('Webhook: No user found for email');
      }
    }
    return c.body(null, 200);
  } catch (e) {
    logger.error('Webhook processing error', { error: e.message });
    return c.body(null, 500);
  }
});

// ==== STATIC ROUTES ====
app.get("/api/health", (c) => c.json({ status: "ok", timestamp: Date.now() }));

// ==== AUTH ROUTES ====
app.post("/api/signup", async (c) => {
  try {
    const body = await c.req.json();
    let { email, password, name } = body;

    // Validation
    if (!validateEmail(email)) {
      return c.json({ error: 'Invalid email format or length' }, 400);
    }
    if (!validatePassword(password)) {
      return c.json({ error: 'Password must be 6-72 characters' }, 400);
    }
    if (!validateName(name)) {
      return c.json({ error: 'Name required (max 100 characters)' }, 400);
    }

    email = email.toLowerCase().trim();
    name = escapeHtml(name.trim());

    const hash = await hashPassword(password);
    let insertID = generateUUID()

    try {
      const result = await databaseManager.insertUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, {
        _id: insertID,
        email: email,
        name: name,
        created_at: Date.now()
      });

      const token = await generateToken(insertID);
      await databaseManager.insertAuth(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { email: email, password: hash, userID: insertID });

      // Generate CSRF token
      const csrfToken = generateCSRFToken();
      csrfTokenStore.set(insertID.toString(), { token: csrfToken, timestamp: Date.now() });

      // Set HttpOnly cookie
      setCookie(c, 'token', token, {
        httpOnly: true,
        secure: !isDevelopment,
        sameSite: 'Strict',
        path: '/',
        maxAge: tokenExpirationDays * 24 * 60 * 60
      });

      // Set CSRF token cookie (readable by frontend)
      setCookie(c, 'csrf_token', csrfToken, {
        httpOnly: false,
        secure: !isDevelopment,
        sameSite: 'Lax',
        path: '/',
        maxAge: CSRF_TOKEN_EXPIRY / 1000
      });

      logger.info('Signup success');

      return c.json({
        id: insertID.toString(),
        email: email,
        name: name.trim(),
        tokenExpires: tokenExpireTimestamp()
      }, 201);
    } catch (e) {
      if (e.message?.includes('UNIQUE constraint failed') || e.message?.includes('duplicate key') || e.code === 11000) {
        logger.warn('Signup failed - duplicate account');
        return c.json({ error: "Unable to create account with provided credentials" }, 400);
      }
      throw e;
    }
  } catch (e) {
    logger.error('Signup error', { error: e.message });
    return c.json({ error: "Server error" }, 500);
  }
});

app.post("/api/signin", async (c) => {
  try {
    const body = await c.req.json();
    let { email, password } = body;

    // Validation
    if (!validateEmail(email)) {
      return c.json({ error: 'Invalid credentials' }, 400);
    }
    if (!password || typeof password !== 'string') {
      return c.json({ error: 'Invalid credentials' }, 400);
    }

    email = email.toLowerCase().trim();
    logger.debug('Attempting signin');

    // Check if auth exists
    const auth = await databaseManager.findAuth(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { email: email });
    if (!auth) {
      logger.debug('Auth record not found');
      return c.json({ error: "Invalid credentials" }, 401);
    }

    //verify
    if (!(await verifyPassword(password, auth.password))) {
      logger.debug('Password verification failed');
      return c.json({ error: "Invalid credentials" }, 401);
    }

    // get user
    const user = await databaseManager.findUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { email: email });
    if (!user) {
      logger.error('User not found for auth record');
      return c.json({ error: "Invalid credentials" }, 401);
    }

    // generate token
    const token = await generateToken(user._id.toString());

    // Generate CSRF token
    const csrfToken = generateCSRFToken();
    csrfTokenStore.set(user._id.toString(), { token: csrfToken, timestamp: Date.now() });

    // Set HttpOnly cookie
    setCookie(c, 'token', token, {
      httpOnly: true,
      secure: !isDevelopment,
      sameSite: 'Strict',
      path: '/',
      maxAge: tokenExpirationDays * 24 * 60 * 60
    });

    // Set CSRF token cookie (readable by frontend)
    setCookie(c, 'csrf_token', csrfToken, {
      httpOnly: false,
      secure: !isDevelopment,
      sameSite: 'Lax',
      path: '/',
      maxAge: CSRF_TOKEN_EXPIRY / 1000
    });

    logger.info('Signin success');

    return c.json({
      id: user._id.toString(),
      email: user.email,
      name: user.name,
      ...(user.subscription && {
        subscription: {
          stripeID: user.subscription.stripeID,
          expires: user.subscription.expires,
          status: user.subscription.status,
        },
      }),
      tokenExpires: tokenExpireTimestamp()
    });
  } catch (e) {
    logger.error('Signin error', { error: e.message });
    return c.json({ error: "Server error" }, 500);
  }
});

app.post("/api/signout", authMiddleware, async (c) => {
  try {
    const userID = c.get('userID');

    // Clear CSRF token from store
    csrfTokenStore.delete(userID);

    // Clear the HttpOnly cookie
    deleteCookie(c, 'token', {
      httpOnly: true,
      secure: !isDevelopment,
      sameSite: 'Strict',
      path: '/'
    });

    // Clear the CSRF token cookie
    deleteCookie(c, 'csrf_token', {
      httpOnly: false,
      secure: !isDevelopment,
      sameSite: 'Lax',
      path: '/'
    });

    logger.info('Signout success');
    return c.json({ message: "Signed out successfully" });
  } catch (e) {
    logger.error('Signout error', { error: e.message });
    return c.json({ error: "Server error" }, 500);
  }
});


// ==== USAGE TRACKING ====
app.post("/api/usage", authMiddleware, async (c) => {
  try {
    const userID = c.get('userID');
    const body = await c.req.json();
    const { operation } = body; // "check" or "track"

    if (!operation || !['check', 'track'].includes(operation)) {
      return c.json({ error: "Invalid operation. Must be 'check' or 'track'" }, 400);
    }

    // Get user
    const user = await databaseManager.findUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { _id: userID });
    if (!user) return c.json({ error: "User not found" }, 404);

    // Check if user is a subscriber - subscribers get unlimited
    const isSubscriber = user.subscription?.status === 'active' &&
      (!user.subscription?.expires || user.subscription.expires > Math.floor(Date.now() / 1000));

    if (isSubscriber) {
      return c.json({
        remaining: -1,
        total: -1,
        isSubscriber: true,
        subscription: {
          status: user.subscription.status,
          expiresAt: user.subscription.expires ? new Date(user.subscription.expires * 1000).toISOString() : null
        }
      });
    }

    // Get usage limit from environment
    const limit = parseInt(process.env.FREE_USAGE_LIMIT || '20');
    const now = Math.floor(Date.now() / 1000);

    // Initialize usage if not set
    let usage = user.usage || { count: 0, reset_at: null };

    // Check if we need to reset (30 days = 2592000 seconds)
    if (!usage.reset_at || now > usage.reset_at) {
      const newResetAt = now + (30 * 24 * 60 * 60); // 30 days from now
      // Reset usage - atomic set operation
      await databaseManager.updateUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
        { _id: userID },
        { $set: { usage: { count: 0, reset_at: newResetAt } } }
      );
      usage = { count: 0, reset_at: newResetAt };
    }

    if (operation === 'track') {
      // Atomic increment first to prevent race conditions
      // Then verify we haven't exceeded the limit
      await databaseManager.updateUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
        { _id: userID },
        { $inc: { 'usage.count': 1 } }
      );

      // Re-read user to get actual count after atomic increment
      const updatedUser = await databaseManager.findUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { _id: userID });
      const actualCount = updatedUser?.usage?.count || 1;

      // If we exceeded the limit, rollback the increment and return 429
      if (actualCount > limit) {
        await databaseManager.updateUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
          { _id: userID },
          { $inc: { 'usage.count': -1 } }
        );
        return c.json({
          error: "Usage limit reached",
          remaining: 0,
          total: limit,
          isSubscriber: false
        }, 429);
      }

      usage.count = actualCount;
    }

    // Return usage info (with subscription details for free users too)
    return c.json({
      remaining: Math.max(0, limit - usage.count),
      total: limit,
      isSubscriber: false,
      used: usage.count,
      subscription: user.subscription ? {
        status: user.subscription.status,
        expiresAt: user.subscription.expires ? new Date(user.subscription.expires * 1000).toISOString() : null
      } : null
    });

  } catch (error) {
    logger.error('Usage tracking error', { error: error.message });
    return c.json({ error: "Server error" }, 500);
  }
});

// ==== PAYMENT ROUTES ====
app.post("/api/checkout", authMiddleware, csrfProtection, async (c) => {
  try {
    const userID = c.get('userID');
    const body = await c.req.json();
    const { email, lookup_key } = body;

    if (!email || !lookup_key) return c.json({ error: "Missing email or lookup_key" }, 400);

    // Verify the email matches the authenticated user
    const user = await databaseManager.findUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { _id: userID });
    if (!user || user.email !== email) return c.json({ error: "Email mismatch" }, 403);

    const prices = await stripe.prices.list({ lookup_keys: [lookup_key], expand: ["data.product"] });

    if (!prices.data || prices.data.length === 0) {
      return c.json({ error: `No price found for lookup_key: ${lookup_key}` }, 400);
    }

    // Use FRONTEND_URL env var or origin header, fallback to localhost for dev
    const origin = process.env.FRONTEND_URL || c.req.header('origin') || `http://localhost:${port}`;

    const session = await stripe.checkout.sessions.create({
      customer_email: email,
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: prices.data[0].id, quantity: 1 }],
      billing_address_collection: "auto",
      success_url: `${origin}/app/payment?success=true`,
      cancel_url: `${origin}/app/payment?canceled=true`,
      subscription_data: { metadata: { email } },
    });
    return c.json({ url: session.url, id: session.id, customerID: session.customer });
  } catch (e) {
    logger.error('Checkout session error', { error: e.message });
    return c.json({ error: "Stripe session failed" }, 500);
  }
});

app.post("/api/portal", authMiddleware, csrfProtection, async (c) => {
  try {
    const userID = c.get('userID');
    const body = await c.req.json();
    const { customerID } = body;

    if (!customerID) return c.json({ error: "Missing customerID" }, 400);

    // Verify the customerID matches the authenticated user's subscription
    const user = await databaseManager.findUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { _id: userID });
    if (!user || (user.subscription?.stripeID && user.subscription.stripeID !== customerID)) {
      return c.json({ error: "Unauthorized customerID" }, 403);
    }

    // Use FRONTEND_URL env var or origin header, fallback to localhost for dev
    const origin = process.env.FRONTEND_URL || c.req.header('origin') || `http://localhost:${port}`;
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerID,
      return_url: `${origin}/app/payment?portal=return`,
    });
    return c.json({ url: portalSession.url, id: portalSession.id });
  } catch (e) {
    logger.error('Portal session error', { error: e.message });
    return c.json({ error: "Stripe portal failed" }, 500);
  }
});

// ==== DOMAIN CHECK ROUTE ====

// Rate limiter for /api/check — sliding window, 30 requests per minute per IP
const CHECK_RATE_LIMIT = 30;
const CHECK_RATE_WINDOW_MS = 60 * 1000;
const CHECK_RATE_MAX_ENTRIES = 10000;
const checkRateStore = new Map(); // IP -> { timestamps: number[] }

/**
 * Rate limit middleware for domain check endpoint
 *
 * Enforces a sliding window of CHECK_RATE_LIMIT requests per CHECK_RATE_WINDOW_MS
 * per IP address. Returns 429 when limit is exceeded. Uses evictOldestEntries
 * for memory management.
 *
 * @async
 * @param {Context} c - Hono context
 * @param {Function} next - Next middleware function
 * @returns {Promise<Response|void>} 429 error or continues to next middleware
 */
async function checkRateLimit(c, next) {
  // Prefer x-forwarded-for (reverse proxy), fall back to x-real-ip, then remote address
  const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim()
    || c.req.header('x-real-ip')
    || c.req.raw?.socket?.remoteAddress
    || 'unknown';
  const now = Date.now();

  let entry = checkRateStore.get(ip);
  if (!entry) {
    entry = { timestamps: [] };
    checkRateStore.set(ip, entry);
  }

  // Remove timestamps outside the window
  entry.timestamps = entry.timestamps.filter((t) => now - t < CHECK_RATE_WINDOW_MS);

  if (entry.timestamps.length >= CHECK_RATE_LIMIT) {
    return c.json({ error: 'Rate limit exceeded. Try again shortly.' }, 429);
  }

  entry.timestamps.push(now);

  // LRU eviction if store is too large
  evictOldestEntries(checkRateStore, CHECK_RATE_MAX_ENTRIES, (v) => v.timestamps[v.timestamps.length - 1] || 0);

  await next();
}

// Periodic cleanup of stale rate limit entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of checkRateStore.entries()) {
    entry.timestamps = entry.timestamps.filter((t) => now - t < CHECK_RATE_WINDOW_MS);
    if (entry.timestamps.length === 0) {
      checkRateStore.delete(ip);
    }
  }
}, 5 * 60 * 1000);

/**
 * WHOIS server map keyed by TLD
 *
 * Maps each supported TLD to its authoritative WHOIS server hostname.
 * WHOIS (port 43 TCP) is the most reliable method for checking domain
 * registration status.
 *
 * @type {Object<string, string>}
 */
const WHOIS_SERVERS = {
  com: 'whois.verisign-grs.com',
  net: 'whois.verisign-grs.com',
  org: 'whois.pir.org',
  io: 'whois.nic.io',
  co: 'whois.registry.co',
  xyz: 'whois.nic.xyz',
  ai: 'whois.nic.ai',
  shop: 'whois.nic.shop',
  site: 'whois.nic.site',
  tech: 'whois.nic.tech',
};

/**
 * RDAP endpoint map for TLDs without WHOIS servers
 *
 * Some TLDs (.dev, .app) have no WHOIS server — only RDAP.
 * The correct endpoint is pubapi.registry.google.
 *
 * @type {Object<string, string>}
 */
const RDAP_SERVERS = {
  dev: 'https://pubapi.registry.google/rdap/domain/',
  app: 'https://pubapi.registry.google/rdap/domain/',
};

const SUPPORTED_TLDS = [...Object.keys(WHOIS_SERVERS), ...Object.keys(RDAP_SERVERS)];
const WHOIS_TIMEOUT_MS = 5000;
const RDAP_TIMEOUT_MS = 5000;

/** Patterns in WHOIS response indicating domain is not registered */
const WHOIS_AVAILABLE_PATTERNS = [
  'no match', 'not found', 'no data found', 'no entries found',
  'no object found', 'status: free', 'status: available',
  'is available', 'domain not found',
];

/** Patterns in WHOIS response indicating domain is registered */
const WHOIS_TAKEN_PATTERNS = [
  'domain name:', 'registrar:', 'creation date:', 'registry domain',
  'registered on:', 'nserver:', 'name server:',
];

/**
 * Query WHOIS server via raw TCP socket
 *
 * Opens a TCP connection to the WHOIS server on port 43, sends the domain
 * name, and collects the response. Uses a timeout to avoid hanging on
 * unreachable servers. This is the same protocol the `whois` CLI uses.
 *
 * @async
 * @param {string} server - WHOIS server hostname
 * @param {string} domain - Domain to query
 * @returns {Promise<string>} Raw WHOIS response text
 * @throws {Error} On connection failure, timeout, or socket error
 */
function queryWhois(server, domain) {
  return new Promise((resolve, reject) => {
    let data = '';
    const socket = net.createConnection(43, server, () => {
      socket.write(domain + '\r\n');
    });

    socket.setTimeout(WHOIS_TIMEOUT_MS);
    socket.setEncoding('utf8');

    socket.on('data', (chunk) => { data += chunk; });
    socket.on('end', () => resolve(data));
    socket.on('timeout', () => { socket.destroy(); reject(new Error('WHOIS timeout')); });
    socket.on('error', (err) => reject(err));
  });
}

/**
 * Check domain availability via WHOIS lookup
 *
 * Queries the TLD's authoritative WHOIS server and parses the response
 * for known available/taken patterns. WHOIS is authoritative for registration
 * status — more reliable than DNS which only checks configured records.
 *
 * @async
 * @param {string} tld - Top-level domain
 * @param {string} fqdn - Fully qualified domain name
 * @returns {Promise<{available: boolean|null, status: string, method: string}>}
 */
async function checkDomainWhois(tld, fqdn) {
  const server = WHOIS_SERVERS[tld];
  try {
    const response = await queryWhois(server, fqdn);
    const lower = response.toLowerCase();

    // Check taken patterns first — WHOIS boilerplate text often contains
    // words like "available" in legal disclaimers, causing false positives
    if (WHOIS_TAKEN_PATTERNS.some((p) => lower.includes(p))) {
      return { available: false, status: 'taken', method: 'whois' };
    }

    if (WHOIS_AVAILABLE_PATTERNS.some((p) => lower.includes(p))) {
      return { available: true, status: 'available', method: 'whois' };
    }

    return { available: null, status: 'whois-unclear', method: 'whois' };
  } catch {
    return null; // Signal to fall back to DNS
  }
}

/**
 * DNS error codes that indicate no domain records exist
 * @type {Set<string>}
 */
const DNS_NOT_FOUND_CODES = new Set(['ENOTFOUND', 'NODATA', 'SERVFAIL', 'REFUSED']);

/**
 * Check domain availability via DNS resolution (fallback)
 *
 * Queries DNS for A, AAAA, and NS records. If any return data, the domain
 * is taken. If none return data and errors indicate nonexistence, it's
 * likely available. Less authoritative than WHOIS — registered domains
 * with no DNS records will appear available.
 *
 * Note: DNS queries go to the system resolver. For additional privacy,
 * configure DNS-over-TLS (DoT) or DNS-over-HTTPS (DoH) at the OS level.
 *
 * @async
 * @param {string} fqdn - Fully qualified domain name
 * @returns {Promise<{available: boolean|null, status: string, method: string}>}
 */
async function checkDomainDNS(fqdn) {
  try {
    const results = await Promise.allSettled([
      dns.promises.resolve(fqdn, 'A'),
      dns.promises.resolve(fqdn, 'AAAA'),
      dns.promises.resolve(fqdn, 'NS'),
    ]);

    const hasRecords = results.some(
      (r) => r.status === 'fulfilled' && r.value.length > 0
    );

    if (hasRecords) {
      return { available: false, status: 'taken', method: 'dns' };
    }

    const hasNotFound = results.some(
      (r) => r.status === 'rejected' && r.reason?.code === 'ENOTFOUND'
    );

    const allRecognizedErrors = results.every(
      (r) => r.status === 'rejected' && DNS_NOT_FOUND_CODES.has(r.reason?.code)
    );

    if (hasNotFound || allRecognizedErrors) {
      return { available: true, status: 'available', method: 'dns' };
    }

    return { available: null, status: 'dns-inconclusive', method: 'dns' };
  } catch {
    return { available: null, status: 'dns-error', method: 'dns' };
  }
}

/**
 * Check domain availability via RDAP lookup
 *
 * Queries the TLD's RDAP endpoint. 200 = taken, 404 = available.
 * Used for TLDs without WHOIS servers (.dev, .app).
 *
 * @async
 * @param {string} tld - Top-level domain
 * @param {string} fqdn - Fully qualified domain name
 * @returns {Promise<{available: boolean|null, status: string, method: string}|null>}
 */
async function checkDomainRdap(tld, fqdn) {
  const baseUrl = RDAP_SERVERS[tld];
  if (!baseUrl) return null;

  try {
    const res = await fetch(`${baseUrl}${fqdn}`, {
      signal: AbortSignal.timeout(RDAP_TIMEOUT_MS),
      headers: {
        'Accept': 'application/rdap+json',
        'User-Agent': 'Domain-Checker/1.0'
      }
    });

    if (res.status === 404) {
      return { available: true, status: 'available', method: 'rdap' };
    }
    if (res.status === 200) {
      return { available: false, status: 'taken', method: 'rdap' };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Check single domain via WHOIS, RDAP, or DNS fallback
 *
 * For most TLDs: tries WHOIS first (authoritative). For .dev/.app:
 * tries RDAP (their only lookup protocol). Falls back
 * to DNS resolution if both fail.
 *
 * @async
 * @param {string} tld - Top-level domain
 * @param {string} name - Base domain name
 * @returns {Promise<{tld: string, domain: string, available: boolean|null, status: string, method: string}>}
 */
async function checkSingleDomain(tld, name) {
  const fqdn = `${name}.${tld}`;

  // Try RDAP for .dev/.app — they have no WHOIS
  if (RDAP_SERVERS[tld]) {
    const rdapResult = await checkDomainRdap(tld, fqdn);
    if (rdapResult) {
      return { tld, domain: fqdn, ...rdapResult };
    }
  }

  // Try WHOIS for all other TLDs (authoritative)
  if (WHOIS_SERVERS[tld]) {
    const whoisResult = await checkDomainWhois(tld, fqdn);
    if (whoisResult) {
      return { tld, domain: fqdn, ...whoisResult };
    }
  }

  // DNS fallback for unreachable servers
  const dnsResult = await checkDomainDNS(fqdn);
  return { tld, domain: fqdn, ...dnsResult };
}

/**
 * Check domain availability across multiple TLDs via WHOIS + DNS fallback
 *
 * Fans out concurrent WHOIS checks for each TLD. Falls back to DNS for
 * TLDs with unreachable WHOIS servers. Results sorted: available first,
 * then taken, then unknown. Uses POST to keep domain queries out of URLs/logs.
 *
 * @route POST /api/check
 * @param {Object} body - JSON request body
 * @param {string} body.domain - Base domain name (alphanumeric + hyphens only)
 * @returns {Array<{tld: string, domain: string, available: boolean|null, status: string, method: string}>}
 */
app.post("/api/check", checkRateLimit, async (c) => {
  let domain;
  try {
    const body = await c.req.json();
    domain = body.domain;
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }

  if (!domain) {
    return c.json({ error: 'Missing domain in request body' }, 400);
  }

  const name = domain.toLowerCase().trim().replace(/\s+/g, '');

  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(name) || name.length > 63) {
    return c.json({ error: 'Invalid domain name. Use alphanumeric characters and hyphens only.' }, 400);
  }

  const results = await Promise.allSettled(
    SUPPORTED_TLDS.map((tld) => checkSingleDomain(tld, name))
  );

  const output = results
    .map((r) => {
      if (r.status === 'fulfilled') return r.value;
      return { tld: 'unknown', domain: '', available: null, status: 'error', method: 'none' };
    })
    .sort((a, b) => {
      // Available first, then taken, then unknown
      const order = (v) => v === true ? 0 : v === false ? 1 : 2;
      return order(a.available) - order(b.available);
    });

  c.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  c.header('Pragma', 'no-cache');
  return c.json(output);
});

// ==== STATIC FILE SERVING (Production) ====
// All /api/* routes are handled above. Everything else is static/SPA.
const staticDir = resolve(__dirname, config.staticDir);

// Serve static assets - skip /api/* paths
app.use('*', async (c, next) => {
  // Skip API routes - they're handled by route handlers above
  if (c.req.path.startsWith('/api/')) {
    return next();
  }

  // Try to serve static file
  const staticMiddleware = serveStatic({ root: staticDir });
  return staticMiddleware(c, next);
});

// SPA fallback - serve index.html for client-side routing
app.get('*', async (c) => {
  // Skip API routes
  if (c.req.path.startsWith('/api/')) {
    return c.json({ error: 'Not found' }, 404);
  }

  try {
    const indexPath = resolve(staticDir, 'index.html');
    const file = await promisify(readFile)(indexPath);
    return c.html(new TextDecoder().decode(file));
  } catch {
    return c.text("Welcome to Skateboard API", 200);
  }
});

// ==== ERROR HANDLER ====
app.onError((err, c) => {
  const requestId = Math.random().toString(36).substr(2, 9);

  logger.error('Unhandled error occurred', {
    message: err.message,
    stack: isDevelopment ? err.stack : undefined,
    path: redactPath(c.req.path),
    method: c.req.method,
    requestId
  });

  return c.json({
    error: isDevelopment ? err.message : 'Internal server error',
    ...(isDevelopment && { stack: err.stack })
  }, 500);
});

// ==== UTILITY FUNCTIONS ====

/**
 * Check if the server is running in production mode
 *
 * Reads the ENV environment variable. Returns true only when
 * ENV is explicitly set to "production".
 *
 * @returns {boolean} True if ENV === "production"
 */
function isProd() {
  if (typeof process.env.ENV === "undefined") {
    return false
  } else if (process.env.ENV === "production") {
    return true
  } else {
    return false
  }
}

/**
 * Load environment variables from local .env file
 *
 * Reads key=value pairs from backend/.env into process.env. Creates .env
 * from .env.example if it doesn't exist. Handles quoted values, comments,
 * and values containing '=' characters. Only called in non-production mode.
 *
 * @returns {void}
 */
function loadLocalENV() {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const envFilePath = resolve(__dirname, './.env');
  const envExamplePath = resolve(__dirname, './.env.example');

  // Check if .env exists, if not create it from .env.example
  try {
    statSync(envFilePath);
  } catch (err) {
    // .env doesn't exist, try to create it from .env.example
    try {
      const exampleData = readFileSync(envExamplePath, 'utf8');
      writeFileSync(envFilePath, exampleData);
    } catch (exampleErr) {
      console.error('Failed to create .env from template:', exampleErr);
      return;
    }
  }

  try {
    const data = readFileSync(envFilePath, 'utf8');
    const lines = data.split(/\r?\n/);
    for (let line of lines) {
      if (!line || line.trim().startsWith('#')) continue;

      // Split only on first = and handle quoted values
      let [key, ...valueParts] = line.split('=');
      let value = valueParts.join('='); // Rejoin in case value contains =

      if (key && value) {
        key = key.trim();
        value = value.trim();
        // Remove surrounding quotes if present
        value = value.replace(/^["']|["']$/g, '');
        process.env[key] = value;
      }
    }
  } catch (err) {
    console.error('Failed to load .env file:', err);
  }
}

// ==== SERVER STARTUP ====
const server = serve({
  fetch: app.fetch,
  port,
  hostname: '::'  // Listen on both IPv4 and IPv6
}, (info) => {
  logger.info('Server started successfully', {
    port: info.port,
    environment: isDevelopment ? 'development' : 'production'
  });
});

// Handle graceful shutdown on SIGTERM and SIGINT - NEED THIS FOR PROXY
if (typeof process !== 'undefined') {
  const gracefulShutdown = async (signal) => {
    console.log(`${signal} received. Shutting down gracefully...`);

    // Close HTTP server first
    server.close(async () => {
      console.log('Server closed');

      // Close all database connections with error handling
      try {
        await databaseManager.closeAll();
        console.log('Database connections closed');
      } catch (err) {
        console.error('Error closing database connections:', err);
      }

      process.exit(0);
    });

    // Force exit after 10 seconds if graceful shutdown hangs
    setTimeout(() => {
      console.error('Forced shutdown after timeout');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}
