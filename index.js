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
  : ['http://localhost:3000', 'http://localhost:3001'];

// ========================================
// 🔧 CORS CONFIGURATION - FIXED
// ========================================

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
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

// ✅ FIX: Webhook endpoint should bypass CORS entirely
app.use((req, res, next) => {
  // Webhook endpoint - allow all origins
  if (req.path === '/api/webhook/admin') {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    return next(); // ✅ Skip CORS middleware for webhooks
  }
  
  // All other endpoints use CORS
  cors(corsOptions)(req, res, next);
});

app.use(express.json());

app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`\n${'='.repeat(70)}`);
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  if (req.method === 'POST' && req.body) {
    console.log('Request Body:', JSON.stringify(req.body, null, 2));
  }
  console.log('='.repeat(70));
  next();
});

// ========================================
// 🔐 DATA STRUCTURES
// ========================================

const userSessions = new Map();
const registeredUsers = new Map();
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'ADMIN_MASTER_KEY';
const ADMIN_API_SECRET = process.env.ADMIN_API_SECRET || 'ADMIN_MASTER_SECRET';
const ADMIN_SESSION_ID = 'ADMIN_MASTER_SESSION';
const masterSignals = new Map();
const userStrategies = new Map();
const strategyPositions = new Map();
const webhookLogs = new Map();

let adminExecutionEnabled = true;

// ========================================
// 🔧 UTILITY FUNCTIONS
// ========================================

function generateSignature(method, endpoint, queryString = '', payload = '', apiSecret) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signatureData = method + timestamp + endpoint + queryString + payload;
  const signature = crypto.createHmac('sha256', apiSecret).update(signatureData).digest('hex');
  return { signature, timestamp };
}

function getAuthHeaders(method, endpoint, queryString = '', payload = '', apiKey, apiSecret) {
  if (!apiKey || !apiSecret) throw new Error('API credentials not configured');
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
  return accountType === 'testnet' ? 'https://cdn-ind.testnet.deltaex.org' : 'https://api.india.delta.exchange';
}

function validateSession(req, res, next) {
  const sessionId = req.headers['x-session-id'];
  if (!sessionId || !userSessions.has(sessionId)) {
    return res.status(401).json({ success: false, error: 'Invalid or expired session. Please login again.' });
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

// ✅ Helper to format error messages properly
function formatErrorMessage(error) {
  if (typeof error === 'string') return error;
  if (error && typeof error === 'object') {
    if (error.code) {
      const errorMessages = {
        'out_of_bankruptcy': 'Insufficient margin - Order would cause liquidation',
        'insufficient_margin': 'Insufficient margin available',
        'invalid_leverage': 'Invalid leverage setting',
        'position_size_exceeded': 'Position size limit exceeded',
        'invalid_reduce_only_order': 'Invalid reduce-only order - No position to close',
        'no_position_to_close': 'No position available to close',
        'insufficient_balance': 'Insufficient balance for this order'
      };
      return errorMessages[error.code] || `Error: ${error.code}`;
    }
    if (error.message) return error.message;
    return JSON.stringify(error);
  }
  return 'Unknown error';
}

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

    console.log(`   📤 Placing order:`, JSON.stringify(orderPayload, null, 2));

    const response = await axios.post(`${baseUrl}${endpoint}`, orderPayload, {
      headers,
      timeout: 10000,
      validateStatus: (status) => status < 500
    });

    console.log(`   📥 Response Status: ${response.status}`);
    console.log(`   📥 Response Data:`, JSON.stringify(response.data, null, 2));

    if (response.status === 200 && response.data.success) {
      return { success: true, order: response.data.result };
    } else {
      const errorMsg = formatErrorMessage(response.data.error) || 'Order placement failed';
      console.error(`   ❌ Order failed:`, errorMsg);
      
      // ✅ Extract balance info from Delta's error response if available
      let balanceInfo = null;
      if (response.data.error && response.data.error.code === 'insufficient_margin') {
        balanceInfo = {
          available: 0,
          required: 0,
          shortfall: 0,
          message: 'Insufficient margin - Check your Delta Exchange account'
        };
      }
      
      return { success: false, error: errorMsg, balanceInfo };
    }
  } catch (error) {
    console.error(`   ❌ Order exception:`, error.message);
    if (error.response) {
      console.error(`   Response Status:`, error.response.status);
      console.error(`   Response Data:`, JSON.stringify(error.response.data, null, 2));
      const errorMsg = formatErrorMessage(error.response.data?.error) || error.message;
      
      // Extract balance info if available
      let balanceInfo = null;
      if (error.response.data?.error?.code === 'insufficient_margin') {
        balanceInfo = {
          available: 0,
          required: 0,
          shortfall: 0,
          message: 'Insufficient margin - Check your Delta Exchange account'
        };
      }
      
      return { success: false, error: errorMsg, balanceInfo };
    }
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
// ✅ FIXED: Volume Calculation (Always Returns Integer)
// ========================================

function calculateVolume(volumeValue, volumeType, accountBalance, currentPrice) {
  // Direct lot size
  if (!volumeType || volumeType === 'volume') {
    const parsed = Math.floor(parseFloat(volumeValue));
    return parsed > 0 ? parsed : 1;
  }
  
  // USD amount
  if (volumeType === 'USD') {
    if (!currentPrice || currentPrice <= 0) {
      console.log(`   ⚠️ Invalid price for USD calculation, defaulting to 1 lot`);
      return 1;
    }
    const calculatedLots = Math.floor(parseFloat(volumeValue) / currentPrice);
    return calculatedLots > 0 ? calculatedLots : 1;
  }
  
  // Equity percentage
  if (volumeType === 'equity_percent') {
    if (!accountBalance || accountBalance <= 0) {
      console.log(`   ⚠️ Invalid balance for equity_percent calculation, defaulting to 1 lot`);
      return 1;
    }
    const tradingAmount = (accountBalance * parseFloat(volumeValue)) / 100;
    if (!currentPrice || currentPrice <= 0) {
      console.log(`   ⚠️ Invalid price for equity_percent calculation, defaulting to 1 lot`);
      return 1;
    }
    const calculatedLots = Math.floor(tradingAmount / currentPrice);
    return calculatedLots > 0 ? calculatedLots : 1;
  }
  
  // Default
  return 1;
}

const ACTION_MAPPINGS = {
  'buy': 'BUY', 'long': 'BUY', 'sell': 'SELL', 'short': 'SELL',
  'exitlong': 'EXIT_LONG', 'exitshort': 'EXIT_SHORT',
  'closelong': 'CLOSE_LONG', 'closeshort': 'CLOSE_SHORT',
  'closelongsell': 'REVERSE_TO_SHORT', 'closeshortbuy': 'REVERSE_TO_LONG',
  'closelongbuy': 'REENTER_LONG', 'closeshortsell': 'REENTER_SHORT',
  'exit': 'EXIT_ALL', 'close': 'EXIT_ALL'
};

// ========================================
// 🔵 HELPER: Get Actual Position from Delta Exchange
// ========================================

async function getActualPosition(productId, apiKey, apiSecret, baseUrl) {
  try {
    console.log(`   🔍 Fetching actual position for product ID: ${productId}`);
    
    const endpoint = '/v2/positions';
    const queryString = `?product_id=${productId}`;
    const headers = getAuthHeaders('GET', endpoint, queryString, '', apiKey, apiSecret);

    const response = await axios.get(`${baseUrl}${endpoint}${queryString}`, { 
      headers, 
      timeout: 10000,
      validateStatus: (status) => status < 500
    });

    console.log(`   📥 Position API Response Status: ${response.status}`);

    if (response.data.success && response.data.result) {
      const position = response.data.result;
      const positionSize = Math.abs(parseFloat(position.size || 0));
      const rawSize = parseFloat(position.size || 0);
      const positionSide = rawSize > 0 ? 'buy' : rawSize < 0 ? 'sell' : null;
      
      console.log(`   📊 Raw Size: ${rawSize}, Absolute Size: ${positionSize}, Side: ${positionSide}`);
      
      return {
        exists: positionSize > 0,
        size: positionSize,
        side: positionSide,
        productId: position.product_id
      };
    }

    console.log(`   ⚠️ No position found or API returned no result`);
    return { exists: false, size: 0, side: null, productId };
  } catch (error) {
    console.error(`   ❌ Error fetching position:`, error.message);
    if (error.response) {
      console.error(`   Response:`, JSON.stringify(error.response.data, null, 2));
    }
    return { exists: false, size: 0, side: null, productId };
  }
}

// ========================================
// 🔵 SIGNAL EXECUTION FUNCTIONS - SMART APPROACH
// ========================================

async function executeBuySignal(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    console.log(`\n   🟢 Executing BUY signal for ${user.email}`);
    console.log(`   📊 Symbol: ${symbol}, Quantity: ${quantity}`);

    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      console.error(`   ❌ Symbol ${symbol} not found`);
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    let orderSize = Math.floor(parseFloat(quantity || 1));
    if (orderSize <= 0) orderSize = 1;

    console.log(`   📦 Product ID: ${product.id}, Order Size: ${orderSize}`);

    const orderPayload = {
      product_id: product.id,
      side: 'buy',
      order_type: options.order_type || 'market_order',
      size: orderSize
    };

    if (options.order_type === 'limit_order' && options.price) {
      orderPayload.limit_price = options.price.toString();
    }

    // ✅ SMART APPROACH: Let Delta Exchange validate balance
    const result = await placeOrder(orderPayload, user.apiKey, user.apiSecret, user.baseUrl);

    if (result.success) {
      console.log(`   ✅ BUY order placed successfully. Order ID: ${result.order.id}`);
      
      const positionKey = getPositionKey(userToken, strategyTag, symbol, 'buy');
      if (strategyPositions.has(positionKey)) {
        const existingPos = strategyPositions.get(positionKey);
        existingPos.size += orderSize;
        existingPos.orderIds.push(result.order.id);
        existingPos.lastUpdated = new Date();
      } else {
        strategyPositions.set(positionKey, {
          userToken, strategyTag, symbol, side: 'buy', size: orderSize,
          orderIds: [result.order.id], createdAt: new Date(), lastUpdated: new Date()
        });
      }
      updateStrategyTracking(userToken, strategyTag, symbol);
      return { success: true, orderId: result.order.id, message: `Bought ${orderSize} contracts` };
    }
    
    console.error(`   ❌ BUY order failed: ${result.error}`);
    return { 
      success: false, 
      error: result.error,
      balanceInfo: result.balanceInfo // Pass through Delta's balance info if available
    };
  } catch (error) {
    console.error(`   ❌ BUY signal exception:`, error.message);
    return { success: false, error: error.message };
  }
}

async function executeSellSignal(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    console.log(`\n   🔴 Executing SELL signal for ${user.email}`);
    console.log(`   📊 Symbol: ${symbol}, Quantity: ${quantity}`);

    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      console.error(`   ❌ Symbol ${symbol} not found`);
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    let orderSize = Math.floor(parseFloat(quantity || 1));
    if (orderSize <= 0) orderSize = 1;

    console.log(`   📦 Product ID: ${product.id}, Order Size: ${orderSize}`);

    const orderPayload = {
      product_id: product.id,
      side: 'sell',
      order_type: options.order_type || 'market_order',
      size: orderSize
    };

    if (options.order_type === 'limit_order' && options.price) {
      orderPayload.limit_price = options.price.toString();
    }

    // ✅ SMART APPROACH: Let Delta Exchange validate balance
    const result = await placeOrder(orderPayload, user.apiKey, user.apiSecret, user.baseUrl);

    if (result.success) {
      console.log(`   ✅ SELL order placed successfully. Order ID: ${result.order.id}`);
      
      const positionKey = getPositionKey(userToken, strategyTag, symbol, 'sell');
      if (strategyPositions.has(positionKey)) {
        const existingPos = strategyPositions.get(positionKey);
        existingPos.size += orderSize;
        existingPos.orderIds.push(result.order.id);
        existingPos.lastUpdated = new Date();
      } else {
        strategyPositions.set(positionKey, {
          userToken, strategyTag, symbol, side: 'sell', size: orderSize,
          orderIds: [result.order.id], createdAt: new Date(), lastUpdated: new Date()
        });
      }
      updateStrategyTracking(userToken, strategyTag, symbol);
      return { success: true, orderId: result.order.id, message: `Sold ${orderSize} contracts` };
    }
    
    console.error(`   ❌ SELL order failed: ${result.error}`);
    return { 
      success: false, 
      error: result.error,
      balanceInfo: result.balanceInfo
    };
  } catch (error) {
    console.error(`   ❌ SELL signal exception:`, error.message);
    return { success: false, error: error.message };
  }
}

// ========================================
// 🔵 FIXED: EXIT LONG SIGNAL (Partial Exit Support)
// ========================================

async function executeExitLongSignal(userToken, strategyTag, symbol, exitQuantity, user) {
  try {
    console.log(`\n   🔵 Executing EXIT LONG signal for ${user.email}`);
    console.log(`   📊 Symbol: ${symbol}, Exit Quantity: ${exitQuantity}`);

    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      console.error(`   ❌ Symbol ${symbol} not found`);
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    console.log(`   📦 Product ID: ${product.id}`);

    // Fetch actual position from Delta Exchange
    const actualPosition = await getActualPosition(product.id, user.apiKey, user.apiSecret, user.baseUrl);

    if (!actualPosition.exists) {
      console.log(`   ⚠️ No position found for ${symbol} - Skipping`);
      return { success: true, message: 'No long position to exit - Skipped', skipped: true };
    }

    if (actualPosition.side !== 'buy') {
      console.log(`   ⚠️ Position is ${actualPosition.side}, not buy - Skipping`);
      return { success: true, message: `Position is ${actualPosition.side}, not long - Skipped`, skipped: true };
    }

    console.log(`   📊 Actual Position Size: ${actualPosition.size}`);

    // ✅ Calculate exit size properly
    let exitSize;
    if (exitQuantity === null || exitQuantity === undefined) {
      // Full exit
      exitSize = actualPosition.size;
      console.log(`   📊 Full exit: ${exitSize} contracts`);
    } else {
      // Partial exit
      const parsedQty = Math.floor(parseFloat(exitQuantity));
      
      if (parsedQty < 1) {
        console.log(`   ⚠️ Exit quantity ${exitQuantity} is less than 1 contract, exiting full position`);
        exitSize = actualPosition.size;
      } else if (parsedQty >= actualPosition.size) {
        console.log(`   ⚠️ Exit quantity ${parsedQty} >= position size ${actualPosition.size}, closing full position`);
        exitSize = actualPosition.size;
      } else {
        exitSize = parsedQty;
        console.log(`   📊 Partial exit: ${exitSize} of ${actualPosition.size} contracts`);
      }
    }

    // ✅ FIX: For partial exits, DO NOT use reduce_only flag
    // For full exits, use reduce_only flag
    const isFullExit = exitSize >= actualPosition.size;
    
    const closePayload = {
      product_id: product.id,
      side: 'sell',
      order_type: 'market_order',
      size: exitSize
    };

    // ✅ Only add reduce_only for full exits
    if (isFullExit) {
      closePayload.reduce_only = true;
      console.log(`   🔒 Full exit - Using reduce_only flag`);
    } else {
      console.log(`   📊 Partial exit - NOT using reduce_only flag`);
    }

    const result = await placeOrder(closePayload, user.apiKey, user.apiSecret, user.baseUrl);
    
    if (result.success) {
      console.log(`   ✅ EXIT LONG successful. Order ID: ${result.order.id}`);
      
      // Update tracking
      const buyPositionKey = getPositionKey(userToken, strategyTag, symbol, 'buy');
      const buyPosition = strategyPositions.get(buyPositionKey);
      
      if (buyPosition) {
        buyPosition.size -= exitSize;
        buyPosition.lastUpdated = new Date();
        
        if (buyPosition.size <= 0) {
          strategyPositions.delete(buyPositionKey);
          console.log(`   📊 Position fully closed in tracking`);
        } else {
          console.log(`   📊 Position updated: ${buyPosition.size} remaining in tracking`);
        }
      }
      
      return { 
        success: true, 
        orderId: result.order.id,
        message: `Exited ${exitSize} contracts${isFullExit ? ' (full exit)' : ' (partial exit)'}`
      };
    }
    
    const errorMsg = formatErrorMessage(result.error);
    console.error(`   ❌ EXIT LONG failed: ${errorMsg}`);
    
    // If error is about no position, return success with skip
    if (errorMsg.includes('reduce-only') || errorMsg.includes('No position')) {
      return { success: true, message: 'No position to exit - Skipped', skipped: true };
    }
    
    return { 
      success: false, 
      error: errorMsg,
      balanceInfo: result.balanceInfo
    };
  } catch (error) {
    console.error(`   ❌ EXIT LONG exception:`, error.message);
    return { success: false, error: error.message };
  }
}

// ========================================
// 🔵 FIXED: EXIT SHORT SIGNAL (Partial Exit Support)
// ========================================

async function executeExitShortSignal(userToken, strategyTag, symbol, exitQuantity, user) {
  try {
    console.log(`\n   🔵 Executing EXIT SHORT signal for ${user.email}`);
    console.log(`   📊 Symbol: ${symbol}, Exit Quantity: ${exitQuantity}`);

    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      console.error(`   ❌ Symbol ${symbol} not found`);
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    console.log(`   📦 Product ID: ${product.id}`);

    const actualPosition = await getActualPosition(product.id, user.apiKey, user.apiSecret, user.baseUrl);

    if (!actualPosition.exists) {
      console.log(`   ⚠️ No position found for ${symbol} - Skipping`);
      return { success: true, message: 'No short position to exit - Skipped', skipped: true };
    }

    if (actualPosition.side !== 'sell') {
      console.log(`   ⚠️ Position is ${actualPosition.side}, not sell - Skipping`);
      return { success: true, message: `Position is ${actualPosition.side}, not short - Skipped`, skipped: true };
    }

    console.log(`   📊 Actual Position Size: ${actualPosition.size}`);

    // ✅ Calculate exit size properly
    let exitSize;
    if (exitQuantity === null || exitQuantity === undefined) {
      exitSize = actualPosition.size;
      console.log(`   📊 Full exit: ${exitSize} contracts`);
    } else {
      const parsedQty = Math.floor(parseFloat(exitQuantity));
      
      if (parsedQty < 1) {
        console.log(`   ⚠️ Exit quantity ${exitQuantity} is less than 1 contract, exiting full position`);
        exitSize = actualPosition.size;
      } else if (parsedQty >= actualPosition.size) {
        console.log(`   ⚠️ Exit quantity ${parsedQty} >= position size ${actualPosition.size}, closing full position`);
        exitSize = actualPosition.size;
      } else {
        exitSize = parsedQty;
        console.log(`   📊 Partial exit: ${exitSize} of ${actualPosition.size} contracts`);
      }
    }

    const isFullExit = exitSize >= actualPosition.size;
    
    const closePayload = {
      product_id: product.id,
      side: 'buy',
      order_type: 'market_order',
      size: exitSize
    };

    // ✅ Only add reduce_only for full exits
    if (isFullExit) {
      closePayload.reduce_only = true;
      console.log(`   🔒 Full exit - Using reduce_only flag`);
    } else {
      console.log(`   📊 Partial exit - NOT using reduce_only flag`);
    }

    const result = await placeOrder(closePayload, user.apiKey, user.apiSecret, user.baseUrl);
    
    if (result.success) {
      console.log(`   ✅ EXIT SHORT successful. Order ID: ${result.order.id}`);
      
      const sellPositionKey = getPositionKey(userToken, strategyTag, symbol, 'sell');
      const sellPosition = strategyPositions.get(sellPositionKey);
      
      if (sellPosition) {
        sellPosition.size -= exitSize;
        sellPosition.lastUpdated = new Date();
        
        if (sellPosition.size <= 0) {
          strategyPositions.delete(sellPositionKey);
          console.log(`   📊 Position fully closed in tracking`);
        } else {
          console.log(`   📊 Position updated: ${sellPosition.size} remaining in tracking`);
        }
      }
      
      return { 
        success: true, 
        orderId: result.order.id,
        message: `Exited ${exitSize} contracts${isFullExit ? ' (full exit)' : ' (partial exit)'}`
      };
    }
    
    const errorMsg = formatErrorMessage(result.error);
    console.error(`   ❌ EXIT SHORT failed: ${errorMsg}`);
    
    if (errorMsg.includes('reduce-only') || errorMsg.includes('No position')) {
      return { success: true, message: 'No position to exit - Skipped', skipped: true };
    }
    
    return { 
      success: false, 
      error: errorMsg,
      balanceInfo: result.balanceInfo
    };
  } catch (error) {
    console.error(`   ❌ EXIT SHORT exception:`, error.message);
    return { success: false, error: error.message };
  }
}

async function executeCloseLongSignal(userToken, strategyTag, symbol, user) {
  console.log(`\n   🔴 Executing CLOSE LONG (full exit) for ${user.email}`);
  return executeExitLongSignal(userToken, strategyTag, symbol, null, user);
}

async function executeCloseShortSignal(userToken, strategyTag, symbol, user) {
  console.log(`\n   🔴 Executing CLOSE SHORT (full exit) for ${user.email}`);
  return executeExitShortSignal(userToken, strategyTag, symbol, null, user);
}

async function executeExitAllSignal(userToken, strategyTag, symbol, user) {
  try {
    console.log(`\n   🔴 Executing EXIT ALL for ${user.email}`);
    
    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      console.error(`   ❌ Symbol ${symbol} not found`);
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    const actualPosition = await getActualPosition(product.id, user.apiKey, user.apiSecret, user.baseUrl);
    
    if (!actualPosition.exists) {
      console.log(`   ⚠️ No position found for ${symbol} - Skipping`);
      return { success: true, message: 'No position to exit - Skipped', skipped: true };
    }

    const closePayload = {
      product_id: product.id,
      side: actualPosition.side === 'buy' ? 'sell' : 'buy',
      order_type: 'market_order',
      size: actualPosition.size,
      reduce_only: true
    };

    const result = await placeOrder(closePayload, user.apiKey, user.apiSecret, user.baseUrl);
    
    if (result.success) {
      console.log(`   ✅ Position closed. Order ID: ${result.order.id}`);
      
      const buyPositionKey = getPositionKey(userToken, strategyTag, symbol, 'buy');
      const sellPositionKey = getPositionKey(userToken, strategyTag, symbol, 'sell');
      strategyPositions.delete(buyPositionKey);
      strategyPositions.delete(sellPositionKey);
      
      return { success: true, orderId: result.order.id, message: 'Position closed successfully' };
    }
    
    const errorMsg = formatErrorMessage(result.error);
    console.error(`   ❌ EXIT ALL failed: ${errorMsg}`);
    
    if (errorMsg.includes('reduce-only') || errorMsg.includes('No position')) {
      return { success: true, message: 'No position to exit - Skipped', skipped: true };
    }
    
    return { 
      success: false, 
      error: errorMsg,
      balanceInfo: result.balanceInfo
    };
  } catch (error) {
    console.error(`   ❌ EXIT ALL exception:`, error.message);
    return { success: false, error: error.message };
  }
}

async function executeReverseToShort(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    console.log(`\n   🔄 Executing REVERSE TO SHORT for ${user.email}`);
    
    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    const actualPosition = await getActualPosition(product.id, user.apiKey, user.apiSecret, user.baseUrl);
    
    if (actualPosition.exists && actualPosition.side === 'buy') {
      console.log(`   📊 Closing existing long position first...`);
      const closeResult = await executeCloseLongSignal(userToken, strategyTag, symbol, user);
      if (!closeResult.success && !closeResult.skipped) {
        console.log(`   ⚠️ Failed to close long position: ${closeResult.error}`);
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    console.log(`   📊 Opening new short position...`);
    return await executeSellSignal(userToken, strategyTag, symbol, quantity, user, options);
  } catch (error) {
    console.error(`   ❌ REVERSE TO SHORT exception:`, error.message);
    return { success: false, error: error.message };
  }
}

async function executeReverseToLong(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    console.log(`\n   🔄 Executing REVERSE TO LONG for ${user.email}`);
    
    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    const actualPosition = await getActualPosition(product.id, user.apiKey, user.apiSecret, user.baseUrl);
    
    if (actualPosition.exists && actualPosition.side === 'sell') {
      console.log(`   📊 Closing existing short position first...`);
      const closeResult = await executeCloseShortSignal(userToken, strategyTag, symbol, user);
      if (!closeResult.success && !closeResult.skipped) {
        console.log(`   ⚠️ Failed to close short position: ${closeResult.error}`);
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    console.log(`   📊 Opening new long position...`);
    return await executeBuySignal(userToken, strategyTag, symbol, quantity, user, options);
  } catch (error) {
    console.error(`   ❌ REVERSE TO LONG exception:`, error.message);
    return { success: false, error: error.message };
  }
}

async function executeReenterLong(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    console.log(`\n   🔁 Executing REENTER LONG for ${user.email}`);
    
    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    const actualPosition = await getActualPosition(product.id, user.apiKey, user.apiSecret, user.baseUrl);
    
    if (actualPosition.exists && actualPosition.side === 'buy') {
      console.log(`   📊 Closing existing long position first...`);
      const closeResult = await executeCloseLongSignal(userToken, strategyTag, symbol, user);
      if (!closeResult.success && !closeResult.skipped) {
        console.log(`   ⚠️ Failed to close long position: ${closeResult.error}`);
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    console.log(`   📊 Opening new long position...`);
    return await executeBuySignal(userToken, strategyTag, symbol, quantity, user, options);
  } catch (error) {
    console.error(`   ❌ REENTER LONG exception:`, error.message);
    return { success: false, error: error.message };
  }
}

async function executeReenterShort(userToken, strategyTag, symbol, quantity, user, options = {}) {
  try {
    console.log(`\n   🔁 Executing REENTER SHORT for ${user.email}`);
    
    const product = await getProductBySymbol(symbol, user.baseUrl);
    if (!product) {
      return { success: false, error: `Symbol ${symbol} not found` };
    }

    const actualPosition = await getActualPosition(product.id, user.apiKey, user.apiSecret, user.baseUrl);
    
    if (actualPosition.exists && actualPosition.side === 'sell') {
      console.log(`   📊 Closing existing short position first...`);
      const closeResult = await executeCloseShortSignal(userToken, strategyTag, symbol, user);
      if (!closeResult.success && !closeResult.skipped) {
        console.log(`   ⚠️ Failed to close short position: ${closeResult.error}`);
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    console.log(`   📊 Opening new short position...`);
    return await executeSellSignal(userToken, strategyTag, symbol, quantity, user, options);
  } catch (error) {
    console.error(`   ❌ REENTER SHORT exception:`, error.message);
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
    webhookLogs: webhookLogs.size,
    adminExecutionEnabled
  });
});

// ========================================
// 🔐 AUTHENTICATION
// ========================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { apiKey, apiSecret, accountType } = req.body;

    if (!apiKey || !apiSecret || !accountType) {
      return res.status(400).json({ success: false, error: 'API Key, API Secret, and Account Type are required' });
    }

    if (!['testnet', 'production'].includes(accountType)) {
      return res.status(400).json({ success: false, error: 'Account type must be either "testnet" or "production"' });
    }

    const isAdminLogin = apiKey === ADMIN_API_KEY && apiSecret === ADMIN_API_SECRET;
    const baseUrl = getBaseUrl(accountType);
    const endpoint = '/v2/profile';
    const headers = getAuthHeaders('GET', endpoint, '', '', apiKey, apiSecret);

    const response = await axios.get(`${baseUrl}${endpoint}`, {
      headers,
      timeout: 15000,
      validateStatus: (status) => status < 500
    });

    if (response.status === 200 && response.data.success) {
      const userInfo = response.data.result;

      if (isAdminLogin) {
        userSessions.set(ADMIN_SESSION_ID, {
          apiKey, apiSecret, accountType, baseUrl, userInfo,
          isAdmin: true, userToken: 'ADMIN',
          createdAt: new Date(), lastActivity: new Date()
        });

        console.log('👑 ADMIN USER LOGGED IN');

        return res.json({
          success: true,
          sessionId: ADMIN_SESSION_ID,
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

      let existingUser = Array.from(registeredUsers.values()).find(
        u => u.email === userInfo.email && u.accountType === accountType
      );

      let userToken;

      if (existingUser) {
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
      } else {
        userToken = generateUserToken();
        const newUser = {
          userToken, apiKey, apiSecret, accountType, baseUrl,
          email: userInfo.email, accountName: userInfo.account_name,
          registeredAt: new Date(), lastLogin: new Date(), isActive: true
        };
        registeredUsers.set(userToken, newUser);
        userStrategies.set(userToken, new Map());
        console.log(`🆕 NEW USER: ${userInfo.email} (${userToken})`);
      }

      const sessionId = crypto.randomBytes(32).toString('hex');
      userSessions.set(sessionId, {
        apiKey, apiSecret, accountType, baseUrl, userInfo,
        isAdmin: false, userToken,
        createdAt: new Date(), lastActivity: new Date()
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
      res.status(401).json({
        success: false,
        error: response.data.error?.message || 'Invalid API credentials'
      });
    }
  } catch (error) {
    if (error.response?.data?.error?.code === 'ip_blocked_for_api_key') {
      return res.status(403).json({
        success: false,
        error: 'IP address not whitelisted.',
        code: 'ip_blocked'
      });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/auth/logout', validateSession, (req, res) => {
  const sessionId = req.headers['x-session-id'];
  userSessions.delete(sessionId);
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
      return res.status(403).json({ success: false, error: 'Admin access required' });
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

    res.json({
      success: true,
      users,
      totalUsers: users.length,
      activeUsers: users.filter(u => u.isActive).length
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/admin/users/:userToken', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }

    const { userToken } = req.params;
    const user = registeredUsers.get(userToken);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    registeredUsers.delete(userToken);
    userStrategies.delete(userToken);

    for (const [key, pos] of strategyPositions.entries()) {
      if (pos.userToken === userToken) strategyPositions.delete(key);
    }

    for (const [sessionId, session] of userSessions.entries()) {
      if (session.userToken === userToken) userSessions.delete(sessionId);
    }

    res.json({ success: true, message: 'User removed successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/admin/users/:userToken/toggle', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }

    const { userToken } = req.params;
    const user = registeredUsers.get(userToken);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    user.isActive = !user.isActive;

    if (!user.isActive) {
      for (const [sessionId, session] of userSessions.entries()) {
        if (session.userToken === userToken) userSessions.delete(sessionId);
      }
    }

    res.json({
      success: true,
      message: `User ${user.isActive ? 'activated' : 'deactivated'} successfully`,
      isActive: user.isActive
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========================================
// 👑 ADMIN EXECUTION TOGGLE
// ========================================

app.post('/api/admin/toggle-execution', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }

    adminExecutionEnabled = !adminExecutionEnabled;

    console.log(`\n${'='.repeat(70)}`);
    console.log(`🔄 Admin execution ${adminExecutionEnabled ? 'ENABLED ✅' : 'DISABLED ❌'}`);
    console.log('='.repeat(70));

    res.json({
      success: true,
      adminExecutionEnabled,
      message: `Admin execution ${adminExecutionEnabled ? 'enabled' : 'disabled'}`
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/admin/execution-status', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }

    res.json({
      success: true,
      adminExecutionEnabled
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========================================
// 📡 FIXED: WEBHOOK ENDPOINT - SMART APPROACH
// ========================================

app.post('/api/webhook/admin', async (req, res) => {
  const logId = `LOG_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const logStart = Date.now();
  
  console.log('\n' + '='.repeat(70));
  console.log('📡 WEBHOOK SIGNAL RECEIVED');
  console.log('='.repeat(70));
  
  try {
    const payload = req.body;
    
    // ✅ Log raw payload for debugging
    console.log('📦 Raw Payload:', JSON.stringify(payload, null, 2));
    console.log('🌐 Source IP:', req.ip || req.connection.remoteAddress);
    console.log('🔧 User Agent:', req.headers['user-agent']);
    console.log('📋 Content-Type:', req.headers['content-type']);

    // ✅ Validate payload is JSON
    if (!payload || typeof payload !== 'object') {
      console.error('❌ Invalid payload - not a JSON object');
      webhookLogs.set(logId, {
        id: logId,
        timestamp: new Date(),
        sourceIP: req.ip || req.connection.remoteAddress,
        payload: req.body,
        userAgent: req.headers['user-agent'],
        status: 'rejected',
        error: 'Invalid payload format',
        processingTime: Date.now() - logStart
      });
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid payload format. Expected JSON object.' 
      });
    }

    webhookLogs.set(logId, {
      id: logId,
      timestamp: new Date(),
      sourceIP: req.ip || req.connection.remoteAddress,
      payload: payload,
      userAgent: req.headers['user-agent'],
      status: 'processing'
    });

    const { action, symbol, volume, volume_type, quantity, strategy_tag, order_type = 'MARKET', price } = payload;

    // ✅ Better validation
    if (!action) {
      console.error('❌ Missing required field: action');
      webhookLogs.set(logId, {
        ...webhookLogs.get(logId),
        status: 'rejected',
        error: 'Missing required field: action',
        processingTime: Date.now() - logStart
      });
      return res.status(400).json({ success: false, error: 'Missing required field: action' });
    }

    if (!symbol) {
      console.error('❌ Missing required field: symbol');
      webhookLogs.set(logId, {
        ...webhookLogs.get(logId),
        status: 'rejected',
        error: 'Missing required field: symbol',
        processingTime: Date.now() - logStart
      });
      return res.status(400).json({ success: false, error: 'Missing required field: symbol' });
    }

    if (!strategy_tag) {
      console.error('❌ Missing required field: strategy_tag');
      webhookLogs.set(logId, {
        ...webhookLogs.get(logId),
        status: 'rejected',
        error: 'Missing required field: strategy_tag',
        processingTime: Date.now() - logStart
      });
      return res.status(400).json({ success: false, error: 'Missing required field: strategy_tag' });
    }

    const normalizedAction = ACTION_MAPPINGS[action.toLowerCase()] || action.toUpperCase();
    console.log(`🎯 Action: ${action} → ${normalizedAction}`);
    console.log(`📊 Symbol: ${symbol}`);
    console.log(`🏷️ Strategy: ${strategy_tag}`);
    console.log(`📈 Volume: ${volume || quantity || 'N/A'} (Type: ${volume_type || 'volume'})`);

    const activeUsers = Array.from(registeredUsers.values()).filter(u => u.isActive);
    console.log(`\n👥 Active Users: ${activeUsers.length}`);

    const adminSession = userSessions.get(ADMIN_SESSION_ID);
    if (adminSession && adminExecutionEnabled) {
      const adminUser = {
        userToken: 'ADMIN',
        email: adminSession.userInfo.email,
        apiKey: adminSession.apiKey,
        apiSecret: adminSession.apiSecret,
        baseUrl: adminSession.baseUrl,
        accountType: adminSession.accountType,
        isActive: true
      };
      activeUsers.push(adminUser);
      console.log('👑 Admin included in execution (toggle ENABLED)');
    } else if (adminSession) {
      console.log('⏸️ Admin excluded from execution (toggle DISABLED)');
    }

    if (activeUsers.length === 0) {
      console.log('⚠️ No active users to execute signals');
      webhookLogs.set(logId, {
        ...webhookLogs.get(logId),
        status: 'successful',
        action: normalizedAction,
        symbol,
        executionResults: [],
        processingTime: Date.now() - logStart
      });
      return res.json({ success: true, message: 'No active users', executionResults: [] });
    }

    console.log(`\n${'='.repeat(70)}`);
    console.log(`📢 BROADCASTING TO ${activeUsers.length} USERS`);
    console.log('='.repeat(70));

    const executionResults = [];

    for (const user of activeUsers) {
      const userLabel = user.userToken === 'ADMIN' ? '👑 ADMIN' : user.email;
      console.log(`\n▶️ Processing: ${userLabel}`);
      
      try {
        // ✅ SMART APPROACH: Only fetch price and balance for volume calculation
        // Don't do pre-validation - let Delta Exchange handle it
        let currentPrice = 0;
        let accountBalance = 0;
        
        try {
          const tickerRes = await axios.get(`${user.baseUrl}/v2/tickers/${symbol}`, {
            headers: { 'Content-Type': 'application/json' }, timeout: 5000
          });
          currentPrice = tickerRes.data.result?.mark_price || 0;
          console.log(`   💲 Current Price: $${currentPrice.toFixed(2)}`);
        } catch (err) {
          console.error(`   ⚠️ Failed to fetch price: ${err.message}`);
        }

        try {
          const endpoint = '/v2/wallet/balances';
          const headers = getAuthHeaders('GET', endpoint, '', '', user.apiKey, user.apiSecret);
          const balanceRes = await axios.get(`${user.baseUrl}${endpoint}`, { headers, timeout: 5000 });
          if (balanceRes.data.success) {
            const wallet = balanceRes.data.result.find(w => w.asset_symbol === 'USDT') || 
                          balanceRes.data.result[0];
            accountBalance = parseFloat(wallet?.available_balance || 0);
            console.log(`   💰 Account Balance: $${accountBalance.toFixed(2)}`);
          }
        } catch (err) {
          console.error(`   ⚠️ Failed to fetch balance: ${err.message}`);
        }

        // Calculate volume based on type
        let actualVolume = volume ? calculateVolume(volume, volume_type, accountBalance, currentPrice) : 
                          (quantity ? Math.floor(parseFloat(quantity)) : 1);

        console.log(`   📊 Calculated Volume: ${actualVolume}`);

        const options = { order_type: order_type === 'LIMIT' ? 'limit_order' : 'market_order', price };

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

        const isSkipped = result.skipped || false;
        
        executionResults.push({
          userToken: user.userToken,
          email: user.email,
          success: result.success,
          orderId: result.orderId,
          error: result.error,
          message: result.message,
          skipped: isSkipped,
          calculatedVolume: actualVolume,
          balanceInfo: result.balanceInfo || null
        });

        const resultMessage = result.success 
          ? (isSkipped ? result.message : (result.orderId || result.message || 'Completed'))
          : (result.error || 'Unknown error');
        
        const statusIcon = result.success ? (isSkipped ? '⏭️' : '✅') : '❌';
        console.log(`   ${statusIcon} ${result.success ? 'SUCCESS' : 'FAILED'}: ${resultMessage}`);
      } catch (error) {
        console.error(`   ❌ EXCEPTION: ${error.message}`);
        executionResults.push({
          userToken: user.userToken,
          email: user.email,
          success: false,
          error: error.message
        });
      }
    }

    const successCount = executionResults.filter(r => r.success).length;
    const failedCount = executionResults.filter(r => !r.success).length;
    const skippedCount = executionResults.filter(r => r.skipped).length;
    const logStatus = executionResults.every(r => r.success) ? 'successful' : 
                      executionResults.some(r => r.success) ? 'partial' : 'failed';

    console.log(`\n${'='.repeat(70)}`);
    console.log(`📊 EXECUTION SUMMARY`);
    console.log('='.repeat(70));
    console.log(`✅ Successful: ${successCount}/${executionResults.length}`);
    console.log(`❌ Failed: ${failedCount}/${executionResults.length}`);
    console.log(`⏭️ Skipped: ${skippedCount}/${executionResults.length}`);
    console.log(`📡 Status: ${logStatus.toUpperCase()}`);
    console.log(`⏱️ Processing Time: ${Date.now() - logStart}ms`);
    console.log('='.repeat(70) + '\n');

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
      processingTime: Date.now() - logStart
    });

    const signalId = generateSignalId();
    masterSignals.set(signalId, {
      signalId,
      signal_type: normalizedAction,
      action: normalizedAction,
      symbol,
      volume: volume || quantity || 1,
      volume_type,
      strategy_name: strategy_tag,
      order_type,
      price,
      description: `Webhook signal`,
      created_at: new Date(),
      execution_count: executionResults.length,
      success_count: successCount,
      executionResults,
      source: 'webhook'
    });

    res.json({
      success: true,
      message: `Signal broadcasted to ${activeUsers.length} users`,
      signalId,
      action: normalizedAction,
      symbol,
      strategy_tag,
      execution_count: executionResults.length,
      success_count: successCount,
      failed_count: failedCount,
      skipped_count: skippedCount,
      executionResults,
      adminExecutionEnabled,
      processingTime: Date.now() - logStart
    });
  } catch (error) {
    console.error('\n❌ WEBHOOK ERROR:', error.message);
    console.error(error.stack);
    
    webhookLogs.set(logId, {
      ...webhookLogs.get(logId),
      status: 'failed',
      error: error.message,
      processingTime: Date.now() - logStart
    });
    
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========================================
// 📡 WEBHOOK LOGS & SIGNALS
// ========================================

app.get('/api/admin/webhook-logs', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }

    const { user, limit = 50 } = req.query;
    let logs = Array.from(webhookLogs.values());
    
    console.log(`📋 Fetching webhook logs. Total logs: ${logs.length}`);
    
    if (user && user !== 'all') {
      logs = logs.filter(log => log.executionResults?.some(r => r.userToken === user || r.email === user));
      console.log(`   Filtered by user: ${user}, Result: ${logs.length} logs`);
    }
    
    logs = logs.sort((a, b) => b.timestamp - a.timestamp).slice(0, parseInt(limit));

    const allLogs = Array.from(webhookLogs.values());
    const stats = {
      total: allLogs.length,
      successful: allLogs.filter(l => l.status === 'successful').length,
      failed: allLogs.filter(l => l.status === 'failed').length,
      rejected: allLogs.filter(l => l.status === 'rejected').length
    };

    console.log(`   Stats:`, stats);

    res.json({ success: true, logs, stats });
  } catch (error) {
    console.error('❌ Error fetching webhook logs:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/admin/signals', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }

    const signals = Array.from(masterSignals.values())
      .sort((a, b) => b.created_at - a.created_at)
      .map(signal => ({
        signalId: signal.signalId,
        signal_type: signal.signal_type,
        action: signal.action,
        symbol: signal.symbol,
        volume: signal.volume,
        strategy_name: signal.strategy_name,
        created_at: signal.created_at,
        execution_count: signal.execution_count,
        success_count: signal.success_count,
        success_rate: signal.execution_count > 0 ? ((signal.success_count / signal.execution_count) * 100).toFixed(1) : '0.0',
        source: signal.source || 'manual',
        executionResults: signal.executionResults
      }));

    console.log(`📡 Fetching signals. Total: ${signals.length}`);

    res.json({ success: true, signals });
  } catch (error) {
    console.error('❌ Error fetching signals:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/admin/signals/:signalId', validateSession, (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }
    const { signalId } = req.params;
    if (!masterSignals.has(signalId)) {
      return res.status(404).json({ success: false, error: 'Signal not found' });
    }
    masterSignals.delete(signalId);
    console.log(`🗑️ Signal deleted: ${signalId}`);
    res.json({ success: true, message: 'Signal deleted successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/user/signals', validateSession, (req, res) => {
  try {
    if (isAdmin(req)) {
      return res.status(403).json({ success: false, error: 'This endpoint is for regular users only' });
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
          created_at: signal.created_at,
          execution_count: signal.execution_count,
          success_count: signal.success_count,
          success_rate: signal.execution_count > 0 ? ((signal.success_count / signal.execution_count) * 100).toFixed(1) : '0.0',
          userExecution: userExecution ? {
            success: userExecution.success,
            orderId: userExecution.orderId,
            error: userExecution.error,
            message: userExecution.message,
            skipped: userExecution.skipped
          } : null
        };
      });

    res.json({ success: true, signals });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========================================
// 📜 TRADING ENDPOINTS
// ========================================

app.get('/api/symbols', validateSession, async (req, res) => {
  try {
    const { baseUrl } = req.userSession;
    const response = await axios.get(`${baseUrl}/v2/products`, {
      headers: { 'Content-Type': 'application/json' }, timeout: 10000
    });

    const symbols = response.data.result
      .filter(p => p.contract_type === 'perpetual_futures' && p.trading_status === 'operational')
      .map(p => ({
        symbol: p.symbol, product_id: p.id, description: p.description,
        tick_size: p.tick_size, contract_value: p.contract_value, trading_status: p.trading_status
      }));

    res.json({ success: true, symbols });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/order', validateSession, async (req, res) => {
  try {
    const { product_id, side, order_type, size, limit_price } = req.body;
    const { apiKey, apiSecret, baseUrl } = req.userSession;

    const orderPayload = {
      product_id: parseInt(product_id),
      side, order_type,
      size: parseInt(size)
    };

    if (order_type === 'limit_order' && limit_price) {
      orderPayload.limit_price = limit_price.toString();
    }

    const payload = JSON.stringify(orderPayload);
    const endpoint = '/v2/orders';
    const headers = getAuthHeaders('POST', endpoint, '', payload, apiKey, apiSecret);

    const response = await axios.post(`${baseUrl}${endpoint}`, orderPayload, {
      headers, timeout: 10000, validateStatus: (status) => status < 500
    });

    if (response.status === 200 && response.data.success) {
      res.json({ success: true, order: response.data.result });
    } else {
      res.status(400).json({ success: false, error: response.data.error?.message || 'Order failed' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/positions', validateSession, async (req, res) => {
  try {
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const endpoint = '/v2/positions/margined';
    const headers = getAuthHeaders('GET', endpoint, '', '', apiKey, apiSecret);

    const response = await axios.get(`${baseUrl}${endpoint}`, { headers, timeout: 10000 });

    const positions = response.data.result
      .filter(pos => Math.abs(pos.size) > 0)
      .map(pos => ({
        id: pos.product_id, product_id: pos.product_id, symbol: pos.product_symbol,
        side: pos.size > 0 ? 'buy' : 'sell', size: Math.abs(pos.size),
        entry_price: parseFloat(pos.entry_price || 0),
        unrealized_pnl: parseFloat(pos.unrealized_pnl || 0),
        liquidation_price: parseFloat(pos.liquidation_price || 0),
        leverage: pos.leverage || 1
      }));

    res.json({ success: true, positions });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/position/close', validateSession, async (req, res) => {
  try {
    const { product_id } = req.body;
    const { apiKey, apiSecret, baseUrl } = req.userSession;

    const endpoint = '/v2/positions';
    const queryString = `?product_id=${product_id}`;
    const headers = getAuthHeaders('GET', endpoint, queryString, '', apiKey, apiSecret);

    const positionResponse = await axios.get(`${baseUrl}${endpoint}${queryString}`, { headers, timeout: 10000 });

    if (!positionResponse.data.success || !positionResponse.data.result) {
      return res.status(404).json({ success: false, error: 'No position found' });
    }

    const position = positionResponse.data.result;
    if (position.size === 0) {
      return res.json({ success: true, message: 'No open position to close' });
    }

    const closeOrderPayload = {
      product_id: parseInt(product_id),
      side: position.size > 0 ? 'sell' : 'buy',
      order_type: 'market_order',
      size: Math.abs(position.size),
      reduce_only: true
    };

    const payload = JSON.stringify(closeOrderPayload);
    const orderEndpoint = '/v2/orders';
    const orderHeaders = getAuthHeaders('POST', orderEndpoint, '', payload, apiKey, apiSecret);

    const orderResponse = await axios.post(`${baseUrl}${orderEndpoint}`, closeOrderPayload, {
      headers: orderHeaders, timeout: 10000, validateStatus: (status) => status < 500
    });

    if (orderResponse.status === 200 && orderResponse.data.success) {
      res.json({ success: true, message: 'Position closed successfully', order: orderResponse.data.result });
    } else {
      res.status(400).json({ success: false, error: orderResponse.data.error?.message || 'Failed to close position' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/orders/history', validateSession, async (req, res) => {
  try {
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const limit = req.query.limit || 20;
    const endpoint = '/v2/orders/history';
    const queryString = `?page_size=${limit}`;
    const headers = getAuthHeaders('GET', endpoint, queryString, '', apiKey, apiSecret);

    const response = await axios.get(`${baseUrl}${endpoint}${queryString}`, { headers, timeout: 10000 });

    const orders = response.data.result.map(order => ({
      id: order.id, product_id: order.product_id, symbol: order.product_symbol,
      side: order.side, order_type: order.order_type, size: order.size,
      price: parseFloat(order.limit_price || order.stop_price || 0),
      filled: order.unfilled_size ? order.size - order.unfilled_size : order.size,
      status: order.state, created_at: order.created_at,
      commission: parseFloat(order.commission || 0)
    }));

    res.json({ success: true, orders });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/account', validateSession, async (req, res) => {
  try {
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const endpoint = '/v2/wallet/balances';
    const headers = getAuthHeaders('GET', endpoint, '', '', apiKey, apiSecret);

    const response = await axios.get(`${baseUrl}${endpoint}`, { headers, timeout: 10000 });

    let walletData = response.data.result.find(w => w.asset_symbol === 'USDT') ||
                     response.data.result.find(w => w.asset_symbol === 'USD') ||
                     response.data.result[0] || {};

    const account = {
      asset_symbol: walletData.asset_symbol || 'USDT',
      available_balance: parseFloat(walletData.available_balance || 0),
      total_balance: parseFloat(walletData.balance || 0),
      margin_balance: parseFloat(walletData.available_balance || 0),
      initial_margin: parseFloat(walletData.order_margin || 0) + parseFloat(walletData.position_margin || 0),
      maintenance_margin: parseFloat(walletData.position_margin || 0),
      unrealized_pnl: parseFloat(walletData.unrealized_pnl || 0)
    };

    res.json({ success: true, account });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/market-data', validateSession, async (req, res) => {
  try {
    const { symbol } = req.query;
    const { baseUrl } = req.userSession;
    const response = await axios.get(`${baseUrl}/v2/tickers/${symbol}`, {
      headers: { 'Content-Type': 'application/json' }, timeout: 10000
    });
    res.json({ success: true, data: response.data.result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/product/:productId', validateSession, async (req, res) => {
  try {
    const { productId } = req.params;
    const { baseUrl } = req.userSession;
    const response = await axios.get(`${baseUrl}/v2/products/${productId}`, {
      headers: { 'Content-Type': 'application/json' }, timeout: 10000
    });
    res.json({ success: true, product: response.data.result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/wallet', validateSession, async (req, res) => {
  try {
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const endpoint = '/v2/wallet/balances';
    const headers = getAuthHeaders('GET', endpoint, '', '', apiKey, apiSecret);
    const response = await axios.get(`${baseUrl}${endpoint}`, { headers, timeout: 10000 });
    res.json({ success: true, balances: response.data.result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========================================
// 🧹 CLEANUP
// ========================================

setInterval(() => {
  const now = new Date();
  const sessionTimeout = 24 * 60 * 60 * 1000;
  for (const [sessionId, session] of userSessions.entries()) {
    if (now - session.lastActivity > sessionTimeout) {
      userSessions.delete(sessionId);
    }
  }
}, 60 * 60 * 1000);

setInterval(() => {
  if (webhookLogs.size > 1000) {
    const logsArray = Array.from(webhookLogs.entries());
    logsArray.sort((a, b) => b[1].timestamp - a[1].timestamp);
    webhookLogs.clear();
    logsArray.slice(0, 500).forEach(([key, value]) => webhookLogs.set(key, value));
    console.log('🧹 Cleaned up old webhook logs. Kept 500 most recent.');
  }
}, 60 * 60 * 1000);

app.use((err, req, res, next) => {
  console.error('❌ Server error:', err);
  res.status(500).json({ success: false, error: 'Internal server error', message: err.message });
});

app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Endpoint not found' });
});

app.listen(PORT, () => {
  console.log('\n' + '='.repeat(70));
  console.log('🚀 Delta Trading Bridge v4.0 - SMART WEBHOOK SYSTEM');
  console.log('='.repeat(70));
  console.log(`📡 Server: http://localhost:${PORT}`);
  console.log(`👑 Admin Key: ${ADMIN_API_KEY}`);
  console.log(`🔑 Admin Secret: ${ADMIN_API_SECRET}`);
  console.log(`📡 Webhook: POST /api/webhook/admin`);
  console.log(`👑 Admin Execution: ${adminExecutionEnabled ? 'ENABLED ✅' : 'DISABLED ❌'}`);
  console.log('='.repeat(70));
  console.log('✅ SUPPORTED ACTIONS:');
  console.log('   Entry: buy, sell');
  console.log('   Partial Exit: exitlong, exitshort');
  console.log('   Full Exit: closelong, closeshort');
  console.log('   Reversal: closelongsell, closeshortbuy');
  console.log('   Re-entry: closelongbuy, closeshortsell');
  console.log('   Generic: exit');
  console.log('='.repeat(70));
  console.log('✅ SMART FEATURES:');
  console.log('   - No Pre-Validation: Delta Exchange handles balance checks');
  console.log('   - Volume Types: volume, USD, equity_percent');
  console.log('   - Order Types: MARKET, LIMIT');
  console.log('   - Partial Exits: Works without reduce_only flag');
  console.log('   - Full Exits: Uses reduce_only flag');
  console.log('   - Actual Position Tracking: Real-time from Delta API');
  console.log('   - Error Translation: Human-readable messages');
  console.log('   - Graceful Skipping: No-position exits return success');
  console.log('='.repeat(70) + '\n');
});
