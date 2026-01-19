// <!-- codeables\index.js -->
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()) 
  : [];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    console.error('❌ Blocked by CORS:', origin);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-session-id'],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ========================================
// 🔐 DATA STRUCTURES
// ========================================

// User sessions (temporary, cleared on logout)
const userSessions = new Map();

// REGISTERED USERS (persistent, only admin can remove)
const registeredUsers = new Map();

// Admin credentials from environment variables
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'ADMIN_MASTER_KEY';
const ADMIN_API_SECRET = process.env.ADMIN_API_SECRET || 'ADMIN_MASTER_SECRET';
const ADMIN_SESSION_ID = 'ADMIN_MASTER_SESSION';

// Signal Provider System
const masterSignals = new Map();

// Strategy tracking (per user)
const userStrategies = new Map();
const strategyPositions = new Map();

// Webhook logs storage
const webhookLogs = new Map();

// ========================================
// 🔧 UTILITY FUNCTIONS
// ========================================

function generateSignature(method, endpoint, queryString = '', payload = '', apiSecret) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signatureData = method + timestamp + endpoint + queryString + payload;

  const signature = crypto
    .createHmac('sha256', apiSecret)
    .update(signatureData)
    .digest('hex');

  return { signature, timestamp };
}

function getAuthHeaders(method, endpoint, queryString = '', payload = '', apiKey, apiSecret) {
  if (!apiKey || !apiSecret) {
    throw new Error('API credentials not configured');
  }

  const { signature, timestamp } = generateSignature(method, endpoint, queryString, payload, apiSecret);

  return {
    'api-key': apiKey,
    'timestamp': timestamp,
    'signature': signature,
    'Content-Type': 'application/json',
    'User-Agent': 'delta-trading-bridge-v4'
  };
}

function getBaseUrl(accountType) {
  return accountType === 'testnet'
    ? 'https://cdn-ind.testnet.deltaex.org'
    : 'https://api.india.delta.exchange';
}

function validateSession(req, res, next) {
  const sessionId = req.headers['x-session-id'];

  if (!sessionId || !userSessions.has(sessionId)) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired session. Please login again.'
    });
  }

  req.userSession = userSessions.get(sessionId);
  next();
}

function generateUserToken() {
  const prefix = 'USR';
  const timestamp = Date.now().toString(36).toUpperCase();
  const random = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}_${timestamp}_${random}`;
}

function generateSignalId() {
  const prefix = 'SIG';
  const timestamp = Date.now().toString(36).toUpperCase();
  const random = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `${prefix}_${timestamp}_${random}`;
}

function getPositionKey(userToken, strategyTag, symbol, side) {
  return `${userToken}:${strategyTag}:${symbol}:${side}`;
}

function isAdmin(req) {
  const sessionId = req.headers['x-session-id'];
  const session = userSessions.get(sessionId);

  return sessionId === ADMIN_SESSION_ID || (session && session.isAdmin === true);
}

// ========================================
// 🛠️ HELPER FUNCTIONS
// ========================================

async function getProductBySymbol(symbol, baseUrl) {
  try {
    const response = await axios.get(`${baseUrl}/v2/products`, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });

    return response.data.result.find(p => p.symbol === symbol);
  } catch (error) {
    console.error('❌ Error fetching product:', error.message);
    return null;
  }
}

async function placeOrder(orderPayload, apiKey, apiSecret, baseUrl) {
  try {
    const payload = JSON.stringify(orderPayload);
    const endpoint = '/v2/orders';
    const headers = getAuthHeaders('POST', endpoint, '', payload, apiKey, apiSecret);

    const response = await axios.post(
      `${baseUrl}${endpoint}`,
      orderPayload,
      {
        headers,
        timeout: 10000,
        validateStatus: function (status) {
          return status < 500;
        }
      }
    );

    if (response.status === 200 && response.data.success) {
      return {
        success: true,
        order: response.data.result
      };
    } else {
      return {
        success: false,
        error: response.data.error?.message || 'Order placement failed'
      };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
}

function updateStrategyTracking(userToken, strategyTag, symbol) {
  if (!userStrategies.has(userToken)) {
    userStrategies.set(userToken, new Map());
  }

  const strategies = userStrategies.get(userToken);

  if (!strategies.has(strategyTag)) {
    strategies.set(strategyTag, {
      strategyTag,
      symbols: new Set([symbol]),
      totalOrders: 1,
      createdAt: new Date(),
      lastActivity: new Date()
    });
  } else {
    const strategy = strategies.get(strategyTag);
    strategy.symbols.add(symbol);
    strategy.totalOrders += 1;
    strategy.lastActivity = new Date();
  }
}

// ========================================
// 📊 VOLUME CALCULATION
// ========================================

function calculateVolume(volumeValue, volumeType, accountBalance, currentPrice) {
  if (!volumeType || volumeType === 'volume') {
    // Direct lot size
    return parseInt(volumeValue);
  }
  
  if (volumeType === 'USD') {
    // Calculate lots from USD amount
    if (!currentPrice || currentPrice <= 0) {
      console.log('⚠️ No price available, using volume as-is');
      return parseInt(volumeValue);
    }
    const calculatedLots = Math.floor(volumeValue / currentPrice);
    return calculatedLots > 0 ? calculatedLots : 1;
  }
  
  if (volumeType === 'equity_percent') {
    // Calculate lots from equity percentage
    if (!accountBalance || accountBalance <= 0) {
      console.log('⚠️ No balance available, using volume as-is');
      return parseInt(volumeValue);
    }
    const tradingAmount = (accountBalance * volumeValue) / 100;
    if (!currentPrice || currentPrice <= 0) {
      console.log('⚠️ No price available, using volume as-is');
      return parseInt(volumeValue);
    }
    const calculatedLots = Math.floor(tradingAmount / currentPrice);
    return calculatedLots > 0 ? calculatedLots : 1;
  }
  
  return parseInt(volumeValue);
}

// ========================================
// 🎯 TP/SL CALCULATION
// ========================================

function calculateTPSL(entryPrice, tpslValue, tpslMode, side, isStopLoss) {
  if (!tpslMode || tpslMode === 'level') {
    // Absolute price level
    return tpslValue;
  }
  
  if (tpslMode === 'pips') {
    // Distance in pips (0.0001 for most forex pairs)
    const pipValue = 0.0001;
    const distance = tpslValue * pipValue;
    
    if (isStopLoss) {
      return side === 'buy' ? entryPrice - distance : entryPrice + distance;
    } else {
      return side === 'buy' ? entryPrice + distance : entryPrice - distance;
    }
  }
  
  if (tpslMode === 'points') {
    // Distance in points
    if (isStopLoss) {
      return side === 'buy' ? entryPrice - tpslValue : entryPrice + tpslValue;
    } else {
      return side === 'buy' ? entryPrice + tpslValue : entryPrice - tpslValue;
    }
  }
  
  if (tpslMode === 'percent') {
    // Percentage distance
    const distance = (entryPrice * tpslValue) / 100;
    
    if (isStopLoss) {
      return side === 'buy' ? entryPrice - distance : entryPrice + distance;
    } else {
      return side === 'buy' ? entryPrice + distance : entryPrice - distance;
    }
  }
  
  return tpslValue;
}

// ========================================
// 🔵 ACTION TYPE MAPPINGS
// ========================================

const ACTION_MAPPINGS = {
  // Entry actions
  'buy': 'BUY',
  'long': 'BUY',
  'sell': 'SELL',
  'short': 'SELL',
  
  // Partial exit actions
  'exitlong': 'EXIT_LONG',
  'exitshort': 'EXIT_SHORT',
  
  // Full exit actions
  'closelong': 'CLOSE_LONG',
  'closeshort': 'CLOSE_SHORT',
  
  // Reversal actions
  'closelongsell': 'REVERSE_TO_SHORT',
  'closeshortbuy': 'REVERSE_TO_LONG',
  
  // Re-entry actions
  'closelongbuy': 'REENTER_LONG',
  'closeshortsell': 'REENTER_SHORT',
  
  // Generic exit
  'exit': 'EXIT_ALL',
  'close': 'EXIT_ALL'
};

// ========================================
// 🔵 SIGNAL EXECUTION FUNCTIONS
// ========================================

async function executeBuySignal(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    let orderSize = quantity ? parseInt(quantity) : 1;
    if (orderSize <= 0) orderSize = 1;

    const orderPayload = {
      product_id: product.id,
      side: 'buy',
      order_type: options.order_type || 'market_order',
      size: orderSize
    };

    if (options.order_type === 'limit_order' && options.price) {
      orderPayload.limit_price = options.price.toString();
    }

    const result = await placeOrder(orderPayload, user.apiKey, user.apiSecret, user.baseUrl);

    if (result.success) {
      const positionKey = getPositionKey(userToken, strategyTag, symbol, 'buy');

      if (strategyPositions.has(positionKey)) {
        const existingPos = strategyPositions.get(positionKey);
        existingPos.size += orderSize;
        existingPos.orderIds.push(result.order.id);
        existingPos.lastUpdated = new Date();
      } else {
        strategyPositions.set(positionKey, {
          userToken,
          strategyTag,
          symbol,
          side: 'buy',
          size: orderSize,
          orderIds: [result.order.id],
          createdAt: new Date(),
          lastUpdated: new Date()
        });
      }

      updateStrategyTracking(userToken, strategyTag, symbol);

      return { success: true, orderId: result.order.id };
    } else {
      return { success: false, error: result.error };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function executeSellSignal(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    let orderSize = quantity ? parseInt(quantity) : 1;
    if (orderSize <= 0) orderSize = 1;

    const orderPayload = {
      product_id: product.id,
      side: 'sell',
      order_type: options.order_type || 'market_order',
      size: orderSize
    };

    if (options.order_type === 'limit_order' && options.price) {
      orderPayload.limit_price = options.price.toString();
    }

    const result = await placeOrder(orderPayload, user.apiKey, user.apiSecret, user.baseUrl);

    if (result.success) {
      const positionKey = getPositionKey(userToken, strategyTag, symbol, 'sell');

      if (strategyPositions.has(positionKey)) {
        const existingPos = strategyPositions.get(positionKey);
        existingPos.size += orderSize;
        existingPos.orderIds.push(result.order.id);
        existingPos.lastUpdated = new Date();
      } else {
        strategyPositions.set(positionKey, {
          userToken,
          strategyTag,
          symbol,
          side: 'sell',
          size: orderSize,
          orderIds: [result.order.id],
          createdAt: new Date(),
          lastUpdated: new Date()
        });
      }

      updateStrategyTracking(userToken, strategyTag, symbol);

      return { success: true, orderId: result.order.id };
    } else {
      return { success: false, error: result.error };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function executeExitLongSignal(userToken, strategyTag, symbol, exitQuantity, user) {
  try {
    const buyPositionKey = getPositionKey(userToken, strategyTag, symbol, 'buy');
    const buyPosition = strategyPositions.get(buyPositionKey);

    if (!buyPosition) {
      return { success: true, message: 'No long position to exit' };
    }

    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    let exitSize = exitQuantity ? parseInt(exitQuantity) : buyPosition.size;
    if (exitSize > buyPosition.size) exitSize = buyPosition.size;

    const closePayload = {
      product_id: product.id,
      side: 'sell',
      order_type: 'market_order',
      size: exitSize,
      reduce_only: true
    };

    const result = await placeOrder(closePayload, user.apiKey, user.apiSecret, user.baseUrl);

    if (result.success) {
      buyPosition.size -= exitSize;
      buyPosition.lastUpdated = new Date();

      if (buyPosition.size <= 0) {
        strategyPositions.delete(buyPositionKey);
      }

      return { success: true, orderId: result.order.id };
    } else {
      return { success: false, error: result.error };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function executeExitShortSignal(userToken, strategyTag, symbol, exitQuantity, user) {
  try {
    const sellPositionKey = getPositionKey(userToken, strategyTag, symbol, 'sell');
    const sellPosition = strategyPositions.get(sellPositionKey);

    if (!sellPosition) {
      return { success: true, message: 'No short position to exit' };
    }

    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    let exitSize = exitQuantity ? parseInt(exitQuantity) : sellPosition.size;
    if (exitSize > sellPosition.size) exitSize = sellPosition.size;

    const closePayload = {
      product_id: product.id,
      side: 'buy',
      order_type: 'market_order',
      size: exitSize,
      reduce_only: true
    };

    const result = await placeOrder(closePayload, user.apiKey, user.apiSecret, user.baseUrl);

    if (result.success) {
      sellPosition.size -= exitSize;
      sellPosition.lastUpdated = new Date();

      if (sellPosition.size <= 0) {
        strategyPositions.delete(sellPositionKey);
      }

      return { success: true, orderId: result.order.id };
    } else {
      return { success: false, error: result.error };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function executeCloseLongSignal(userToken, strategyTag, symbol, user) {
  return executeExitLongSignal(userToken, strategyTag, symbol, null, user);
}

async function executeCloseShortSignal(userToken, strategyTag, symbol, user) {
  return executeExitShortSignal(userToken, strategyTag, symbol, null, user);
}

async function executeExitAllSignal(userToken, strategyTag, symbol, user) {
  try {
    const buyPositionKey = getPositionKey(userToken, strategyTag, symbol, 'buy');
    const sellPositionKey = getPositionKey(userToken, strategyTag, symbol, 'sell');

    const buyPosition = strategyPositions.get(buyPositionKey);
    const sellPosition = strategyPositions.get(sellPositionKey);

    if (!buyPosition && !sellPosition) {
      return { success: true, message: 'No positions to exit' };
    }

    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    const closedOrders = [];

    if (buyPosition) {
      const closePayload = {
        product_id: product.id,
        side: 'sell',
        order_type: 'market_order',
        size: buyPosition.size,
        reduce_only: true
      };

      const result = await placeOrder(closePayload, user.apiKey, user.apiSecret, user.baseUrl);
      if (result.success) {
        strategyPositions.delete(buyPositionKey);
        closedOrders.push(result.order.id);
      }
    }

    if (sellPosition) {
      const closePayload = {
        product_id: product.id,
        side: 'buy',
        order_type: 'market_order',
        size: sellPosition.size,
        reduce_only: true
      };

      const result = await placeOrder(closePayload, user.apiKey, user.apiSecret, user.baseUrl);
      if (result.success) {
        strategyPositions.delete(sellPositionKey);
        closedOrders.push(result.order.id);
      }
    }

    return { success: true, orderId: closedOrders.join(',') };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function executeReverseToShort(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    const buyPositionKey = getPositionKey(userToken, strategyTag, symbol, 'buy');
    const buyPosition = strategyPositions.get(buyPositionKey);
    
    // Close long position if exists
    if (buyPosition) {
      await executeCloseLongSignal(userToken, strategyTag, symbol, user);
    }
    
    // Open short position
    return await executeSellSignal(userToken, strategyTag, symbol, quantity, user, options);
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function executeReverseToLong(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    const sellPositionKey = getPositionKey(userToken, strategyTag, symbol, 'sell');
    const sellPosition = strategyPositions.get(sellPositionKey);
    
    // Close short position if exists
    if (sellPosition) {
      await executeCloseShortSignal(userToken, strategyTag, symbol, user);
    }
    
    // Open long position
    return await executeBuySignal(userToken, strategyTag, symbol, quantity, user, options);
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function executeReenterLong(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    const buyPositionKey = getPositionKey(userToken, strategyTag, symbol, 'buy');
    const buyPosition = strategyPositions.get(buyPositionKey);
    
    // Close existing long position
    if (buyPosition) {
      await executeCloseLongSignal(userToken, strategyTag, symbol, user);
    }
    
    // Open new long position
    return await executeBuySignal(userToken, strategyTag, symbol, quantity, user, options);
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function executeReenterShort(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    const sellPositionKey = getPositionKey(userToken, strategyTag, symbol, 'sell');
    const sellPosition = strategyPositions.get(sellPositionKey);
    
    // Close existing short position
    if (sellPosition) {
      await executeCloseShortSignal(userToken, strategyTag, symbol, user);
    }
    
    // Open new short position
    return await executeSellSignal(userToken, strategyTag, symbol, quantity, user, options);
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// ========================================
// 🏥 HEALTH CHECK
// ========================================

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    activeSessions: userSessions.size,
    registeredUsers: registeredUsers.size,
    totalSignals: masterSignals.size,
    webhookLogs: webhookLogs.size
  });
});

// ========================================
// 🔐 AUTHENTICATION
// ========================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { apiKey, apiSecret, accountType } = req.body;

    console.log('📝 Login Request:');
    console.log('  Account Type:', accountType);

    if (!apiKey || !apiSecret || !accountType) {
      return res.status(400).json({
        success: false,
        error: 'API Key, API Secret, and Account Type are required'
      });
    }

    if (!['testnet', 'production'].includes(accountType)) {
      return res.status(400).json({
        success: false,
        error: 'Account type must be either "testnet" or "production"'
      });
    }

    // Check if this is admin login
    const isAdminLogin = apiKey === ADMIN_API_KEY && apiSecret === ADMIN_API_SECRET;

    const baseUrl = getBaseUrl(accountType);
    const endpoint = '/v2/profile';
    const headers = getAuthHeaders('GET', endpoint, '', '', apiKey, apiSecret);

    const response = await axios.get(
      `${baseUrl}${endpoint}`,
      {
        headers,
        timeout: 15000,
        validateStatus: function (status) {
          return status < 500;
        }
      }
    );

    if (response.status === 200 && response.data.success) {
      const userInfo = response.data.result;

      if (isAdminLogin) {
        // Admin login
        const sessionId = ADMIN_SESSION_ID;

        userSessions.set(sessionId, {
          apiKey,
          apiSecret,
          accountType,
          baseUrl,
          userInfo,
          isAdmin: true,
          userToken: 'ADMIN',
          createdAt: new Date(),
          lastActivity: new Date()
        });

        console.log('👑 ADMIN USER LOGGED IN');

        return res.json({
          success: true,
          sessionId,
          userInfo: {
            email: userInfo.email,
            accountName: userInfo.account_name,
            accountType,
            marginMode: userInfo.margin_mode,
            isAdmin: true,
            userToken: 'ADMIN'
          }
        });
      }

      // Regular user login - Check by email
      let existingUser = Array.from(registeredUsers.values()).find(
        u => u.email === userInfo.email && u.accountType === accountType
      );

      let userToken;

      if (existingUser) {
        // User exists, check if active
        if (!existingUser.isActive) {
          return res.status(403).json({
            success: false,
            error: 'Your account has been deactivated by admin. Please contact support.'
          });
        }

        userToken = existingUser.userToken;
        existingUser.lastLogin = new Date();
        existingUser.apiKey = apiKey;
        existingUser.apiSecret = apiSecret;
        existingUser.baseUrl = baseUrl;

        console.log(`✅ Existing user logged in: ${userInfo.email} (${userToken})`);
      } else {
        // New user - auto-register
        userToken = generateUserToken();

        const newUser = {
          userToken,
          apiKey,
          apiSecret,
          accountType,
          baseUrl,
          email: userInfo.email,
          accountName: userInfo.account_name,
          registeredAt: new Date(),
          lastLogin: new Date(),
          isActive: true
        };

        registeredUsers.set(userToken, newUser);
        userStrategies.set(userToken, new Map());

        console.log('='.repeat(70));
        console.log(`🆕 NEW USER AUTO-REGISTERED!`);
        console.log(`  Email: ${userInfo.email}`);
        console.log(`  Token: ${userToken}`);
        console.log(`  Account Type: ${accountType}`);
        console.log(`  Total Users: ${registeredUsers.size}`);
        console.log('='.repeat(70));
      }

      // Create session
      const sessionId = crypto.randomBytes(32).toString('hex');

      userSessions.set(sessionId, {
        apiKey,
        apiSecret,
        accountType,
        baseUrl,
        userInfo,
        isAdmin: false,
        userToken,
        createdAt: new Date(),
        lastActivity: new Date()
      });

      res.json({
        success: true,
        sessionId,
        userInfo: {
          email: userInfo.email,
          accountName: userInfo.account_name,
          accountType,
          marginMode: userInfo.margin_mode,
          isAdmin: false,
          userToken
        }
      });
    } else {
      console.error('❌ Login failed:', response.data);

      res.status(401).json({
        success: false,
        error: response.data.error?.message || 'Invalid API credentials',
        details: response.data.error
      });
    }
  } catch (error) {
    console.error('❌ Login error:', error.message);

    if (error.response?.data?.error?.code === 'ip_blocked_for_api_key') {
      return res.status(403).json({
        success: false,
        error: 'IP address not whitelisted. Please add your IP address to the API key whitelist on Delta Exchange.',
        code: 'ip_blocked'
      });
    }

    res.status(500).json({
      success: false,
      error: error.message || 'An unexpected error occurred'
    });
  }
});

app.post('/api/auth/logout', validateSession, (req, res) => {
  const sessionId = req.headers['x-session-id'];
  userSessions.delete(sessionId);

  console.log('👋 User logged out, session deleted:', sessionId);

  res.json({ success: true, message: 'Logged out successfully' });
});

app.get('/api/auth/validate', validateSession, (req, res) => {
  res.json({
    success: true,
    userInfo: {
      email: req.userSession.userInfo.email,
      accountName: req.userSession.userInfo.account_name,
      accountType: req.userSession.accountType,
      marginMode: req.userSession.userInfo.margin_mode,
      isAdmin: req.userSession.isAdmin || false,
      userToken: req.userSession.userToken
    }
  });
});

// ========================================
// 👥 ADMIN - USER MANAGEMENT
// ========================================

app.get('/api/admin/users', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }

    const users = Array.from(registeredUsers.values()).map(user => ({
      userToken: user.userToken,
      email: user.email,
      accountName: user.accountName,
      accountType: user.accountType,
      registeredAt: user.registeredAt,
      lastLogin: user.lastLogin,
      isActive: user.isActive,
      strategiesCount: userStrategies.get(user.userToken)?.size || 0
    }));

    console.log(`📊 Admin fetching users: ${users.length} total users`);

    res.json({
      success: true,
      users,
      totalUsers: users.length,
      activeUsers: users.filter(u => u.isActive).length
    });
  } catch (error) {
    console.error('❌ Error fetching users:', error.message);

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.delete('/api/admin/users/:userToken', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }

    const { userToken } = req.params;

    const user = registeredUsers.get(userToken);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Remove user
    registeredUsers.delete(userToken);
    userStrategies.delete(userToken);

    // Remove all positions for this user
    for (const [key, pos] of strategyPositions.entries()) {
      if (pos.userToken === userToken) {
        strategyPositions.delete(key);
      }
    }

    // Invalidate all sessions for this user
    for (const [sessionId, session] of userSessions.entries()) {
      if (session.userToken === userToken) {
        userSessions.delete(sessionId);
      }
    }

    console.log(`🗑️ User removed by admin: ${user.email} (${userToken})`);

    res.json({
      success: true,
      message: 'User removed successfully'
    });
  } catch (error) {
    console.error('❌ Error removing user:', error.message);

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/admin/users/:userToken/toggle', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }

    const { userToken } = req.params;

    const user = registeredUsers.get(userToken);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    user.isActive = !user.isActive;

    // If deactivating, invalidate all sessions
    if (!user.isActive) {
      for (const [sessionId, session] of userSessions.entries()) {
        if (session.userToken === userToken) {
          userSessions.delete(sessionId);
        }
      }
    }

    console.log(`🔄 User ${user.isActive ? 'activated' : 'deactivated'}: ${user.email}`);

    res.json({
      success: true,
      message: `User ${user.isActive ? 'activated' : 'deactivated'} successfully`,
      isActive: user.isActive
    });
  } catch (error) {
    console.error('❌ Error toggling user status:', error.message);

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ========================================
// 📡 WEBHOOK LOGGING MIDDLEWARE
// ========================================

const webhookLoggingMiddleware = (req, res, next) => {
  // Only apply to webhook endpoint - Fix the path check
  if (req.path.includes('/webhook/admin') && req.method === 'POST') {
    const logId = `LOG_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    req.webhookLogId = logId;
    req.webhookLogStart = Date.now();
    
    // Store initial log entry
    webhookLogs.set(logId, {
      id: logId,
      timestamp: new Date(),
      sourceIP: req.ip || req.connection.remoteAddress,
      payload: req.body,
      userAgent: req.headers['user-agent'],
      status: 'processing'
    });
    
    // Keep only last 500 logs
    if (webhookLogs.size > 500) {
      const firstKey = webhookLogs.keys().next().value;
      webhookLogs.delete(firstKey);
    }
  }
  
  next();
};

// Apply the middleware BEFORE routes
app.use(webhookLoggingMiddleware);

// ========================================
// 📡 ADMIN WEBHOOK - ENHANCED WITH NEW ACTIONS
// ========================================

app.post('/api/webhook/admin', async (req, res) => {
  const logId = req.webhookLogId;
  
  try {
    const payload = req.body;
    
    console.log('📡 Enhanced Webhook Received:');
    console.log(JSON.stringify(payload, null, 2));

    const { 
      action, 
      symbol, 
      volume, 
      volume_type,
      quantity, // Legacy support
      strategy_tag,
      order_type = 'MARKET',
      price,
      stop_loss,
      take_profit,
      tpsl_mode,
      wait_for_position = 2.0
    } = payload;

    // Validate required fields
    if (!action || !symbol || !strategy_tag) {
      if (logId) {
        webhookLogs.set(logId, {
          ...webhookLogs.get(logId),
          status: 'rejected',
          error: 'Missing required fields',
          processingTime: Date.now() - req.webhookLogStart
        });
      }
      
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: action, symbol, strategy_tag'
      });
    }

    // Normalize action
    const normalizedAction = ACTION_MAPPINGS[action.toLowerCase()] || action.toUpperCase();

    // Get all active users - EXCLUDE ADMIN
    const activeUsers = Array.from(registeredUsers.values()).filter(u => {
      // Check if user is active AND not admin
      const isUserActive = u.isActive;
      const isNotAdmin = u.userToken !== 'ADMIN';
      
      return isUserActive && isNotAdmin;
    });

    if (activeUsers.length === 0) {
      if (logId) {
        webhookLogs.set(logId, {
          ...webhookLogs.get(logId),
          status: 'successful',
          action: normalizedAction,
          symbol,
          executionResults: [],
          processingTime: Date.now() - req.webhookLogStart
        });
      }
      
      console.log('⚠️ No active users to broadcast to (admin excluded)');
      return res.json({
        success: true,
        message: 'No active users to broadcast to',
        executionResults: []
      });
    }

    console.log(`📢 Broadcasting ${normalizedAction} signal to ${activeUsers.length} users (admin excluded)...`);

    const executionResults = [];

    // Execute signal on all active users
    for (const user of activeUsers) {
      try {
        // Get current market price for volume calculation
        let currentPrice = 0;
        try {
          const tickerRes = await axios.get(`${user.baseUrl}/v2/tickers/${symbol}`, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 5000
          });
          currentPrice = tickerRes.data.result?.mark_price || 0;
        } catch (err) {
          console.log(`⚠️ Could not fetch price for ${symbol}, using volume as-is`);
        }

        // Get account balance for volume calculation
        let accountBalance = 0;
        try {
          const endpoint = '/v2/wallet/balances';
          const headers = getAuthHeaders('GET', endpoint, '', '', user.apiKey, user.apiSecret);
          const balanceRes = await axios.get(`${user.baseUrl}${endpoint}`, { headers, timeout: 5000 });
          
          if (balanceRes.data.success) {
            const wallet = balanceRes.data.result.find(w => w.asset_symbol === 'USDT') || 
                          balanceRes.data.result.find(w => w.asset_symbol === 'USD') ||
                          balanceRes.data.result[0];
            accountBalance = parseFloat(wallet?.available_balance || 0);
          }
        } catch (err) {
          console.log(`⚠️ Could not fetch balance for ${user.email}, using volume as-is`);
        }

        // Calculate actual volume
        let actualVolume;
        if (volume) {
          actualVolume = calculateVolume(volume, volume_type, accountBalance, currentPrice);
        } else if (quantity) {
          actualVolume = parseInt(quantity);
        } else {
          actualVolume = 1;
        }

        // Prepare options
        const options = {
          order_type: order_type === 'LIMIT' ? 'limit_order' : 'market_order',
          price,
          stop_loss,
          take_profit,
          tpsl_mode,
          wait_for_position
        };

        let result;

        switch (normalizedAction) {
          case 'BUY':
            result = await executeBuySignal(user.userToken, strategy_tag, symbol, actualVolume, user, options);
            break;

          case 'SELL':
            result = await executeSellSignal(user.userToken, strategy_tag, symbol, actualVolume, user, options);
            break;

          case 'EXIT_LONG':
            result = await executeExitLongSignal(user.userToken, strategy_tag, symbol, actualVolume, user);
            break;

          case 'EXIT_SHORT':
            result = await executeExitShortSignal(user.userToken, strategy_tag, symbol, actualVolume, user);
            break;

          case 'CLOSE_LONG':
            result = await executeCloseLongSignal(user.userToken, strategy_tag, symbol, user);
            break;

          case 'CLOSE_SHORT':
            result = await executeCloseShortSignal(user.userToken, strategy_tag, symbol, user);
            break;

          case 'EXIT_ALL':
            result = await executeExitAllSignal(user.userToken, strategy_tag, symbol, user);
            break;

          case 'REVERSE_TO_SHORT':
            result = await executeReverseToShort(user.userToken, strategy_tag, symbol, actualVolume, user, options);
            break;

          case 'REVERSE_TO_LONG':
            result = await executeReverseToLong(user.userToken, strategy_tag, symbol, actualVolume, user, options);
            break;

          case 'REENTER_LONG':
            result = await executeReenterLong(user.userToken, strategy_tag, symbol, actualVolume, user, options);
            break;

          case 'REENTER_SHORT':
            result = await executeReenterShort(user.userToken, strategy_tag, symbol, actualVolume, user, options);
            break;

          default:
            result = { success: false, error: 'Invalid action type' };
        }

        executionResults.push({
          userToken: user.userToken,
          email: user.email,
          success: result.success,
          orderId: result.orderId,
          error: result.error,
          calculatedVolume: actualVolume
        });

        console.log(`  ${result.success ? '✅' : '❌'} ${user.email}: ${result.success ? 'Success' : result.error}`);

      } catch (error) {
        executionResults.push({
          userToken: user.userToken,
          email: user.email,
          success: false,
          error: error.message
        });
        console.log(`  ❌ ${user.email}: ${error.message}`);
      }
    }

    // Update webhook log with results
    const successCount = executionResults.filter(r => r.success).length;
    const logStatus = executionResults.every(r => r.success) ? 'successful' : 
                      executionResults.some(r => r.success) ? 'partial' : 'failed';

    if (logId) {
      webhookLogs.set(logId, {
        ...webhookLogs.get(logId),
        status: logStatus,
        action: normalizedAction,
        symbol,
        volume,
        volume_type,
        strategy_tag,
        order_type,
        executionResults,
        processingTime: Date.now() - req.webhookLogStart
      });
    }

    // Save signal to history
    const signalId = generateSignalId();
    const signal_data = {
      signalId,
      signal_type: normalizedAction,
      action: normalizedAction,
      symbol,
      volume: volume || quantity || 1,
      volume_type,
      strategy_name: strategy_tag,
      order_type,
      price,
      stop_loss,
      take_profit,
      tpsl_mode,
      description: `Webhook signal from TradingView`,
      created_at: new Date(),
      execution_count: executionResults.length,
      success_count: successCount,
      executionResults,
      source: 'webhook'
    };

    masterSignals.set(signalId, signal_data);

    console.log(`✅ Webhook broadcast completed: ${successCount}/${executionResults.length} successful (admin excluded)`);

    res.json({
      success: true,
      message: `Signal broadcasted to ${activeUsers.length} users (admin excluded)`,
      signalId,
      action: normalizedAction,
      symbol,
      strategy_tag,
      execution_count: executionResults.length,
      success_count: successCount,
      executionResults
    });
  } catch (error) {
    console.error('❌ Enhanced webhook error:', error.message);

    if (logId) {
      webhookLogs.set(logId, {
        ...webhookLogs.get(logId),
        status: 'failed',
        error: error.message,
        processingTime: Date.now() - req.webhookLogStart
      });
    }
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ========================================
// 📡 ADMIN - SIGNAL MANAGEMENT
// ========================================

app.get('/api/admin/signals', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }

    const signals = Array.from(masterSignals.values())
      .sort((a, b) => b.created_at - a.created_at)
      .map(signal => ({
        signalId: signal.signalId,
        signal_type: signal.signal_type,
        action: signal.action,
        symbol: signal.symbol,
        volume: signal.volume,
        volume_type: signal.volume_type,
        strategy_name: signal.strategy_name,
        description: signal.description,
        created_at: signal.created_at,
        execution_count: signal.execution_count,
        success_count: signal.success_count,
        success_rate: signal.execution_count > 0
          ? ((signal.success_count / signal.execution_count) * 100).toFixed(1)
          : '0.0',
        source: signal.source || 'manual',
        executionResults: signal.executionResults
      }));

    res.json({
      success: true,
      signals,
      statistics: {
        totalSignals: signals.length,
        totalExecutions: signals.reduce((sum, s) => sum + s.execution_count, 0),
        totalSuccesses: signals.reduce((sum, s) => sum + s.success_count, 0)
      }
    });
  } catch (error) {
    console.error('❌ Error fetching signals:', error.message);

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.delete('/api/admin/signals/:signalId', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }

    const { signalId } = req.params;

    if (!masterSignals.has(signalId)) {
      return res.status(404).json({
        success: false,
        error: 'Signal not found'
      });
    }

    masterSignals.delete(signalId);

    res.json({
      success: true,
      message: 'Signal deleted successfully'
    });
  } catch (error) {
    console.error('❌ Error deleting signal:', error.message);

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ========================================
// 📡 WEBHOOK LOGS
// ========================================

app.get('/api/admin/webhook-logs', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }

    const { user, limit = 50 } = req.query;
    
    let logs = Array.from(webhookLogs.values());
    
    if (user && user !== 'all') {
      logs = logs.filter(log => 
        log.executionResults?.some(r => r.userToken === user || r.email === user)
      );
    }
    
    logs = logs
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, parseInt(limit));

    const allLogs = Array.from(webhookLogs.values());
    const stats = {
      total: allLogs.length,
      successful: allLogs.filter(l => l.status === 'successful').length,
      failed: allLogs.filter(l => l.status === 'failed').length,
      rejected: allLogs.filter(l => l.status === 'rejected').length
    };

    res.json({
      success: true,
      logs,
      stats
    });
  } catch (error) {
    console.error('❌ Error fetching webhook logs:', error.message);
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ========================================
// 👤 USER - VIEW SIGNALS (Read-only)
// ========================================

app.get('/api/user/signals', validateSession, (req, res) => {
  try {
    if (isAdmin(req)) {
      return res.status(403).json({
        success: false,
        error: 'This endpoint is for regular users only'
      });
    }

    const signals = Array.from(masterSignals.values())
      .sort((a, b) => b.created_at - a.created_at)
      .slice(0, 50)
      .map(signal => {
        const userToken = req.userSession.userToken;
        const userExecution = signal.executionResults?.find(r => r.userToken === userToken);

        return {
          signalId: signal.signalId,
          signal_type: signal.signal_type,
          action: signal.action,
          symbol: signal.symbol,
          volume: signal.volume,
          strategy_name: signal.strategy_name,
          description: signal.description,
          created_at: signal.created_at,
          execution_count: signal.execution_count,
          success_count: signal.success_count,
          success_rate: signal.execution_count > 0
            ? ((signal.success_count / signal.execution_count) * 100).toFixed(1)
            : '0.0',
          userExecution: userExecution ? {
            success: userExecution.success,
            orderId: userExecution.orderId,
            error: userExecution.error
          } : null
        };
      });

    res.json({
      success: true,
      signals
    });
  } catch (error) {
    console.error('❌ Error fetching user signals:', error.message);

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ========================================
// 📜 MANUAL TRADING ENDPOINTS
// ========================================

app.get('/api/symbols', validateSession, async (req, res) => {
  try {
    const { baseUrl } = req.userSession;

    const response = await axios.get(`${baseUrl}/v2/products`, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });

    const symbols = response.data.result
      .filter(product => product.contract_type === 'perpetual_futures' && product.trading_status === 'operational')
      .map(product => ({
        symbol: product.symbol,
        product_id: product.id,
        description: product.description,
        tick_size: product.tick_size,
        contract_value: product.contract_value,
        trading_status: product.trading_status
      }));

    res.json({
      success: true,
      symbols: symbols
    });
  } catch (error) {
    console.error('❌ Error fetching symbols:', error.message);

    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

app.post('/api/order', validateSession, async (req, res) => {
  try {
    const { product_id, side, order_type, size, limit_price } = req.body;
    const { apiKey, apiSecret, baseUrl } = req.userSession;

    const orderPayload = {
      product_id: parseInt(product_id),
      side: side,
      order_type: order_type,
      size: parseInt(size)
    };

    if (order_type === 'limit_order' && limit_price) {
      orderPayload.limit_price = limit_price.toString();
    }

    const payload = JSON.stringify(orderPayload);
    const endpoint = '/v2/orders';
    const headers = getAuthHeaders('POST', endpoint, '', payload, apiKey, apiSecret);

    const response = await axios.post(
      `${baseUrl}${endpoint}`,
      orderPayload,
      {
        headers,
        timeout: 10000,
        validateStatus: function (status) {
          return status < 500;
        }
      }
    );

    if (response.status === 200 && response.data.success) {
      res.json({
        success: true,
        order: response.data.result
      });
    } else {
      res.status(400).json({
        success: false,
        error: response.data.error?.message || 'Order placement failed',
        code: response.data.error?.code,
        details: response.data.error
      });
    }
  } catch (error) {
    console.error('❌ Error placing order:', error.message);

    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message,
      details: error.response?.data?.error
    });
  }
});

app.get('/api/positions', validateSession, async (req, res) => {
  try {
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const endpoint = '/v2/positions/margined';
    const headers = getAuthHeaders('GET', endpoint, '', '', apiKey, apiSecret);

    const response = await axios.get(
      `${baseUrl}${endpoint}`,
      { headers, timeout: 10000 }
    );

    const positions = response.data.result
      .filter(pos => Math.abs(pos.size) > 0)
      .map(pos => ({
        id: pos.product_id,
        product_id: pos.product_id,
        symbol: pos.product_symbol,
        side: pos.size > 0 ? 'buy' : 'sell',
        size: Math.abs(pos.size),
        entry_price: parseFloat(pos.entry_price || 0),
        unrealized_pnl: parseFloat(pos.unrealized_pnl || 0),
        liquidation_price: parseFloat(pos.liquidation_price || 0),
        leverage: pos.leverage || 1
      }));

    res.json({
      success: true,
      positions: positions
    });
  } catch (error) {
    console.error('❌ Error fetching positions:', error.message);

    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

app.post('/api/position/close', validateSession, async (req, res) => {
  try {
    const { product_id } = req.body;
    const { apiKey, apiSecret, baseUrl } = req.userSession;

    const endpoint = '/v2/positions';
    const queryString = `?product_id=${product_id}`;
    const headers = getAuthHeaders('GET', endpoint, queryString, '', apiKey, apiSecret);

    const positionResponse = await axios.get(
      `${baseUrl}${endpoint}${queryString}`,
      { headers, timeout: 10000 }
    );

    if (!positionResponse.data.success || !positionResponse.data.result) {
      return res.status(404).json({
        success: false,
        error: 'No position found for this product'
      });
    }

    const position = positionResponse.data.result;
    const positionSize = position.size;

    if (positionSize === 0) {
      return res.json({
        success: true,
        message: 'No open position to close'
      });
    }

    const closeSide = positionSize > 0 ? 'sell' : 'buy';
    const closeSize = Math.abs(positionSize);

    const closeOrderPayload = {
      product_id: parseInt(product_id),
      side: closeSide,
      order_type: 'market_order',
      size: closeSize,
      reduce_only: true
    };

    const payload = JSON.stringify(closeOrderPayload);
    const orderEndpoint = '/v2/orders';
    const orderHeaders = getAuthHeaders('POST', orderEndpoint, '', payload, apiKey, apiSecret);

    const orderResponse = await axios.post(
      `${baseUrl}${orderEndpoint}`,
      closeOrderPayload,
      {
        headers: orderHeaders,
        timeout: 10000,
        validateStatus: function (status) {
          return status < 500;
        }
      }
    );

    if (orderResponse.status === 200 && orderResponse.data.success) {
      res.json({
        success: true,
        message: 'Position closed successfully',
        order: orderResponse.data.result
      });
    } else {
      res.status(400).json({
        success: false,
        error: orderResponse.data.error?.message || 'Failed to close position'
      });
    }
  } catch (error) {
    console.error('❌ Error closing position:', error.message);

    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

app.get('/api/orders/history', validateSession, async (req, res) => {
  try {
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const limit = req.query.limit || 20;
    const endpoint = '/v2/orders/history';
    const queryString = `?page_size=${limit}`;
    const headers = getAuthHeaders('GET', endpoint, queryString, '', apiKey, apiSecret);

    const response = await axios.get(
      `${baseUrl}${endpoint}${queryString}`,
      { headers, timeout: 10000 }
    );

    const orders = response.data.result.map(order => ({
      id: order.id,
      product_id: order.product_id,
      symbol: order.product_symbol,
      side: order.side,
      order_type: order.order_type,
      size: order.size,
      price: parseFloat(order.limit_price || order.stop_price || 0),
      filled: order.unfilled_size ? order.size - order.unfilled_size : order.size,
      status: order.state,
      created_at: order.created_at,
      commission: parseFloat(order.commission || 0)
    }));

    res.json({
      success: true,
      orders: orders
    });
  } catch (error) {
    console.error('❌ Error fetching order history:', error.message);

    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

app.get('/api/account', validateSession, async (req, res) => {
  try {
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const endpoint = '/v2/wallet/balances';
    const headers = getAuthHeaders('GET', endpoint, '', '', apiKey, apiSecret);

    const response = await axios.get(
      `${baseUrl}${endpoint}`,
      { headers, timeout: 10000 }
    );

    let walletData = response.data.result.find(w => w.asset_symbol === 'USDT');
    if (!walletData) {
      walletData = response.data.result.find(w => w.asset_symbol === 'USD');
    }
    if (!walletData) {
      walletData = response.data.result.find(w => parseFloat(w.balance || 0) > 0);
    }
    if (!walletData) {
      walletData = response.data.result[0] || {};
    }

    const account = {
      asset_symbol: walletData.asset_symbol || 'USDT',
      available_balance: parseFloat(walletData.available_balance || 0),
      total_balance: parseFloat(walletData.balance || 0),
      margin_balance: parseFloat(walletData.available_balance || 0),
      initial_margin: parseFloat(walletData.order_margin || 0) + parseFloat(walletData.position_margin || 0),
      maintenance_margin: parseFloat(walletData.position_margin || 0),
      unrealized_pnl: parseFloat(walletData.unrealized_pnl || 0),
      all_wallets: response.data.result.map(w => ({
        asset: w.asset_symbol,
        balance: parseFloat(w.balance || 0),
        available: parseFloat(w.available_balance || 0)
      }))
    };

    res.json({
      success: true,
      account: account
    });
  } catch (error) {
    console.error('❌ Error fetching account info:', error.message);

    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

app.get('/api/market-data', validateSession, async (req, res) => {
  try {
    const { symbol } = req.query;
    const { baseUrl } = req.userSession;

    const response = await axios.get(`${baseUrl}/v2/tickers/${symbol}`, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });

    res.json({
      success: true,
      data: response.data.result
    });
  } catch (error) {
    console.error('❌ Error fetching market data:', error.message);

    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

app.get('/api/product/:productId', validateSession, async (req, res) => {
  try {
    const { productId } = req.params;
    const { baseUrl } = req.userSession;

    const response = await axios.get(`${baseUrl}/v2/products/${productId}`, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });

    res.json({
      success: true,
      product: response.data.result
    });
  } catch (error) {
    console.error('❌ Error fetching product info:', error.message);

    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

app.get('/api/wallet', validateSession, async (req, res) => {
  try {
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const endpoint = '/v2/wallet/balances';
    const headers = getAuthHeaders('GET', endpoint, '', '', apiKey, apiSecret);

    const response = await axios.get(
      `${baseUrl}${endpoint}`,
      { headers, timeout: 10000 }
    );

    res.json({
      success: true,
      balances: response.data.result
    });
  } catch (error) {
    console.error('❌ Error fetching wallet:', error.message);

    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

// ========================================
// 🧹 CLEANUP & ERROR HANDLING
// ========================================

// Cleanup expired sessions
setInterval(() => {
  const now = new Date();
  const sessionTimeout = 24 * 60 * 60 * 1000; // 24 hours

  for (const [sessionId, session] of userSessions.entries()) {
    if (now - session.lastActivity > sessionTimeout) {
      userSessions.delete(sessionId);
      console.log(`🧹 Cleaned up expired session: ${sessionId}`);
    }
  }
}, 60 * 60 * 1000); // Run every hour

// Cleanup old webhook logs
setInterval(() => {
  const now = new Date();
  const logTimeout = 7 * 24 * 60 * 60 * 1000; // 7 days

  for (const [logId, log] of webhookLogs.entries()) {
    if (now - log.timestamp > logTimeout) {
      webhookLogs.delete(logId);
    }
  }
  
  console.log(`🧹 Webhook logs cleanup: ${webhookLogs.size} logs remaining`);
}, 24 * 60 * 60 * 1000); // Run daily

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Server error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: err.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found'
  });
});

// ========================================
// 🚀 SERVER START
// ========================================

app.listen(PORT, () => {
  console.log('='.repeat(70));
  console.log('🚀 Delta Trading Bridge v4.0 - ENHANCED WEBHOOK SYSTEM');
  console.log('='.repeat(70));
  console.log(`📡 Server running on: http://localhost:${PORT}`);
  console.log(`🔐 Session-based authentication enabled`);
  console.log(`👥 Auto-registration on first login`);
  console.log(`👑 Admin webhook broadcasts to all users (admin excluded)`);
  console.log(`📊 Manual trading enabled for all users`);
  console.log(`📡 Webhook logging enabled`);
  console.log('='.repeat(70));
  console.log('✅ ADMIN CREDENTIALS:');
  console.log(`   API Key: ${ADMIN_API_KEY}`);
  console.log(`   API Secret: ${ADMIN_API_SECRET}`);
  console.log('='.repeat(70));
  console.log('✅ ADMIN WEBHOOK ENDPOINT:');
  console.log('   POST /api/webhook/admin');
  console.log('='.repeat(70));
  console.log('✅ SUPPORTED ACTIONS:');
  console.log('   Entry: buy, sell');
  console.log('   Partial Exit: exitlong, exitshort');
  console.log('   Full Exit: closelong, closeshort');
  console.log('   Reversal: closelongsell, closeshortbuy');
  console.log('   Re-entry: closelongbuy, closeshortsell');
  console.log('   Generic: exit');
  console.log('='.repeat(70));
  console.log('✅ ENHANCED FEATURES:');
  console.log('   - Volume Types: volume, USD, equity_percent');
  console.log('   - TP/SL Modes: level, pips, points, percent');
  console.log('   - Order Types: MARKET, LIMIT');
  console.log('   - Webhook Logging: Real-time monitoring');
  console.log('   - Admin Exclusion: Admin not affected by webhooks');
  console.log('='.repeat(70));
  console.log('');
});
