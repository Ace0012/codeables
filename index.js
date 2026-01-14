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

// User sessions
const userSessions = new Map();

// PHASE 2: Multi-account system
const deltaAccounts = new Map();
const accountStrategies = new Map();
const strategyPositions = new Map();
const orderMetadata = new Map();

// PHASE 3: Signal Provider System
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || '';
const ADMIN_SESSION_ID = 'ADMIN_MASTER_SESSION';
const masterSignals = new Map();
const userSubscriptions = new Map();
const signalExecutions = new Map();

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
    'User-Agent': 'delta-trading-bridge-v3'
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

function generateAccountToken() {
  const prefix = 'ACC';
  const randomPart = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}_${randomPart}`;
}

function getPositionKey(accountToken, strategyTag, symbol, side) {
  return `${accountToken}:${strategyTag}:${symbol}:${side}`;
}

function generateSignalId() {
  const prefix = 'SIG';
  const timestamp = Date.now().toString(36).toUpperCase();
  const random = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `${prefix}_${timestamp}_${random}`;
}

function isAdmin(req) {
  const sessionId = req.headers['x-session-id'];
  const session = userSessions.get(sessionId);
  
  return sessionId === ADMIN_SESSION_ID || 
         (session && session.apiKey === ADMIN_API_KEY);
}

// ========================================
// 🛠️ HELPER FUNCTIONS FOR WEBHOOKS
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

async function placeOrder(orderPayload, account) {
  try {
    const payload = JSON.stringify(orderPayload);
    const endpoint = '/v2/orders';
    const headers = getAuthHeaders('POST', endpoint, '', payload, account.apiKey, account.apiSecret);

    const response = await axios.post(
      `${account.baseUrl}${endpoint}`,
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
    return {
      success: false,
      error: error.message
    };
  }
}

function updateStrategyTracking(accountToken, strategyTag, symbol) {
  if (!accountStrategies.get(accountToken).has(strategyTag)) {
    accountStrategies.get(accountToken).set(strategyTag, {
      strategyTag,
      symbols: new Set([symbol]),
      totalOrders: 1,
      createdAt: new Date(),
      lastActivity: new Date()
    });
  } else {
    const strategy = accountStrategies.get(accountToken).get(strategyTag);
    strategy.symbols.add(symbol);
    strategy.totalOrders += 1;
    strategy.lastActivity = new Date();
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
    totalAccounts: deltaAccounts.size,
    totalStrategies: Array.from(accountStrategies.values()).reduce((sum, map) => sum + map.size, 0),
    activePositions: strategyPositions.size,
    totalSignals: masterSignals.size,
    totalSubscribers: userSubscriptions.size
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
      const sessionId = crypto.randomBytes(32).toString('hex');
      
      const isAdminUser = apiKey === ADMIN_API_KEY;
      
      userSessions.set(sessionId, {
        apiKey,
        apiSecret,
        accountType,
        baseUrl,
        userInfo: response.data.result,
        isAdmin: isAdminUser,
        createdAt: new Date(),
        lastActivity: new Date()
      });

      console.log(`✅ Login successful for user: ${response.data.result.email}`);
      if (isAdminUser) {
        console.log('👑 ADMIN USER LOGGED IN');
      }

      res.json({
        success: true,
        sessionId,
        userInfo: {
          email: response.data.result.email,
          accountName: response.data.result.account_name,
          accountType,
          marginMode: response.data.result.margin_mode,
          isAdmin: isAdminUser
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
  
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

app.get('/api/auth/validate', validateSession, (req, res) => {
  res.json({
    success: true,
    userInfo: {
      email: req.userSession.userInfo.email,
      accountName: req.userSession.userInfo.account_name,
      accountType: req.userSession.accountType,
      marginMode: req.userSession.userInfo.margin_mode,
      isAdmin: req.userSession.isAdmin || false
    }
  });
});

// ========================================
// 🏦 ACCOUNT MANAGEMENT
// ========================================

app.post('/api/accounts/add', validateSession, async (req, res) => {
  try {
    const { apiKey, apiSecret, accountType, accountLabel, ipAddress } = req.body;
    const sessionId = req.headers['x-session-id'];

    console.log('🏦 Adding new Delta Exchange account...');

    if (!apiKey || !apiSecret || !accountType) {
      return res.status(400).json({
        success: false,
        error: 'API Key, API Secret, and Account Type are required'
      });
    }

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

    if (response.status !== 200 || !response.data.success) {
      return res.status(401).json({
        success: false,
        error: 'Invalid API credentials for Delta Exchange account'
      });
    }

    const accountToken = generateAccountToken();

    const accountData = {
      accountToken,
      apiKey,
      apiSecret,
      accountType,
      baseUrl,
      accountLabel: accountLabel || `Account ${deltaAccounts.size + 1}`,
      ipAddress: ipAddress || 'Not specified',
      userEmail: response.data.result.email,
      accountName: response.data.result.account_name,
      addedBy: sessionId,
      createdAt: new Date(),
      lastUsed: new Date()
    };

    deltaAccounts.set(accountToken, accountData);
    accountStrategies.set(accountToken, new Map());

    console.log(`✅ Account added successfully: ${accountToken}`);

    res.json({
      success: true,
      accountToken,
      accountData: {
        accountToken,
        accountLabel: accountData.accountLabel,
        accountType: accountData.accountType,
        userEmail: accountData.userEmail,
        accountName: accountData.accountName,
        ipAddress: accountData.ipAddress,
        createdAt: accountData.createdAt
      }
    });
  } catch (error) {
    console.error('❌ Error adding account:', error.message);
    
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to add account'
    });
  }
});

app.get('/api/accounts', validateSession, (req, res) => {
  try {
    const sessionId = req.headers['x-session-id'];
    
    const userAccounts = Array.from(deltaAccounts.values())
      .filter(acc => acc.addedBy === sessionId)
      .map(acc => ({
        accountToken: acc.accountToken,
        accountLabel: acc.accountLabel,
        accountType: acc.accountType,
        userEmail: acc.userEmail,
        accountName: acc.accountName,
        ipAddress: acc.ipAddress,
        createdAt: acc.createdAt,
        lastUsed: acc.lastUsed,
        strategiesCount: accountStrategies.get(acc.accountToken)?.size || 0
      }));

    res.json({
      success: true,
      accounts: userAccounts,
      totalAccounts: userAccounts.length
    });
  } catch (error) {
    console.error('❌ Error fetching accounts:', error.message);
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.delete('/api/accounts/:accountToken', validateSession, (req, res) => {
  try {
    const { accountToken } = req.params;
    const sessionId = req.headers['x-session-id'];

    const account = deltaAccounts.get(accountToken);

    if (!account) {
      return res.status(404).json({
        success: false,
        error: 'Account not found'
      });
    }

    if (account.addedBy !== sessionId) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized to delete this account'
      });
    }

    deltaAccounts.delete(accountToken);
    accountStrategies.delete(accountToken);
    
    for (const [key, pos] of strategyPositions.entries()) {
      if (pos.accountToken === accountToken) {
        strategyPositions.delete(key);
      }
    }

    console.log(`🗑️ Account deleted: ${accountToken}`);

    res.json({
      success: true,
      message: 'Account deleted successfully'
    });
  } catch (error) {
    console.error('❌ Error deleting account:', error.message);
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/accounts/:accountToken/strategies', validateSession, (req, res) => {
  try {
    const { accountToken } = req.params;

    const account = deltaAccounts.get(accountToken);
    if (!account) {
      return res.status(404).json({
        success: false,
        error: 'Account not found'
      });
    }

    const strategies = accountStrategies.get(accountToken);
    const strategyList = Array.from(strategies.values()).map(s => ({
      strategyTag: s.strategyTag,
      symbols: Array.from(s.symbols),
      totalOrders: s.totalOrders,
      createdAt: s.createdAt,
      lastActivity: s.lastActivity
    }));

    res.json({
      success: true,
      accountToken,
      accountLabel: account.accountLabel,
      strategies: strategyList,
      totalStrategies: strategyList.length
    });
  } catch (error) {
    console.error('❌ Error fetching strategies:', error.message);
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/accounts/:accountToken/positions', validateSession, (req, res) => {
  try {
    const { accountToken } = req.params;
    const { strategy_tag } = req.query;

    const account = deltaAccounts.get(accountToken);
    if (!account) {
      return res.status(404).json({
        success: false,
        error: 'Account not found'
      });
    }

    let positions = Array.from(strategyPositions.values())
      .filter(pos => pos.accountToken === accountToken);

    if (strategy_tag) {
      positions = positions.filter(pos => pos.strategyTag === strategy_tag);
    }

    const positionList = positions.map(pos => ({
      strategyTag: pos.strategyTag,
      symbol: pos.symbol,
      side: pos.side,
      size: pos.size,
      orderIds: pos.orderIds,
      createdAt: pos.createdAt,
      lastUpdated: pos.lastUpdated
    }));

    res.json({
      success: true,
      accountToken,
      accountLabel: account.accountLabel,
      positions: positionList,
      totalPositions: positionList.length
    });
  } catch (error) {
    console.error('❌ Error fetching positions:', error.message);
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/stats', validateSession, (req, res) => {
  try {
    const sessionId = req.headers['x-session-id'];
    
    const userAccounts = Array.from(deltaAccounts.values())
      .filter(acc => acc.addedBy === sessionId);

    const totalStrategies = userAccounts.reduce((sum, acc) => {
      return sum + (accountStrategies.get(acc.accountToken)?.size || 0);
    }, 0);

    const totalPositions = Array.from(strategyPositions.values())
      .filter(pos => userAccounts.some(acc => acc.accountToken === pos.accountToken))
      .length;

    res.json({
      success: true,
      stats: {
        totalAccounts: userAccounts.length,
        totalStrategies,
        totalPositions,
        totalOrders: orderMetadata.size
      }
    });
  } catch (error) {
    console.error('❌ Error fetching stats:', error.message);
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ========================================
// 📡 ENHANCED TRADINGVIEW WEBHOOK - ALL MESSAGE TYPES
// ========================================

app.post('/api/webhook/tradingview', async (req, res) => {
  try {
    const payload = req.body;
    
    console.log('📡 TradingView Webhook Received:');
    console.log(JSON.stringify(payload, null, 2));

    const { account_token, strategy_tag, signal, symbol, quantity, exit_quantity } = payload;

    // Validate required fields
    if (!account_token || !strategy_tag || !signal || !symbol) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: account_token, strategy_tag, signal, symbol'
      });
    }

    // Validate account token
    const account = deltaAccounts.get(account_token);
    if (!account) {
      console.error(`❌ Invalid account token: ${account_token}`);
      return res.status(404).json({
        success: false,
        error: 'Invalid account token'
      });
    }

    console.log(`✅ Account validated: ${account.accountLabel}`);
    account.lastUsed = new Date();

    const normalizedSignal = signal.toUpperCase();

    // Route to appropriate handler based on signal type
    switch (normalizedSignal) {
      case 'BUY':
        return await handleBuySignal(account_token, strategy_tag, symbol, quantity, account, res);
      
      case 'SELL':
        return await handleSellSignal(account_token, strategy_tag, symbol, quantity, account, res);
      
      case 'BUY_EXIT':
      case 'EXIT_BUY':
        return await handleBuyExitSignal(account_token, strategy_tag, symbol, exit_quantity, account, res);
      
      case 'SELL_EXIT':
      case 'EXIT_SELL':
        return await handleSellExitSignal(account_token, strategy_tag, symbol, exit_quantity, account, res);
      
      case 'EXIT':
      case 'EXIT_ALL':
        return await handleExitAllSignal(account_token, strategy_tag, symbol, account, res);
      
      case 'STOP_AND_REVERSE':
      case 'REVERSE':
        return await handleStopAndReverseSignal(account_token, strategy_tag, symbol, quantity, account, res);
      
      default:
        return res.status(400).json({
          success: false,
          error: `Invalid signal type: ${signal}. Valid types: BUY, SELL, BUY_EXIT, SELL_EXIT, EXIT, STOP_AND_REVERSE`
        });
    }

  } catch (error) {
    console.error('❌ Webhook error:', error.message);
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ========================================
// 🔵 BUY SIGNAL HANDLER
// ========================================
async function handleBuySignal(accountToken, strategyTag, symbol, quantity, account, res) {
  try {
    console.log(`🔵 Processing BUY signal for ${symbol}`);

    const product = await getProductBySymbol(symbol, account.baseUrl);
    if (!product) {
      return res.status(404).json({
        success: false,
        error: `Symbol ${symbol} not found`
      });
    }

    let orderSize = quantity ? parseInt(quantity) : 1;
    if (orderSize <= 0) orderSize = 1;

    const orderPayload = {
      product_id: product.id,
      side: 'buy',
      order_type: 'market_order',
      size: orderSize
    };

    const result = await placeOrder(orderPayload, account);

    if (result.success) {
      // Track order metadata
      orderMetadata.set(result.order.id, {
        accountToken,
        strategyTag,
        symbol,
        side: 'buy',
        size: orderSize,
        orderId: result.order.id,
        timestamp: new Date()
      });

      // Update position tracking
      const positionKey = getPositionKey(accountToken, strategyTag, symbol, 'buy');
      
      if (strategyPositions.has(positionKey)) {
        const existingPos = strategyPositions.get(positionKey);
        existingPos.size += orderSize;
        existingPos.orderIds.push(result.order.id);
        existingPos.lastUpdated = new Date();
      } else {
        strategyPositions.set(positionKey, {
          accountToken,
          strategyTag,
          symbol,
          side: 'buy',
          size: orderSize,
          orderIds: [result.order.id],
          createdAt: new Date(),
          lastUpdated: new Date()
        });
      }

      // Update strategy tracking
      updateStrategyTracking(accountToken, strategyTag, symbol);

      console.log(`✅ BUY order placed successfully: ${result.order.id}`);

      return res.json({
        success: true,
        message: 'BUY order placed successfully',
        order: {
          orderId: result.order.id,
          symbol,
          side: 'buy',
          size: orderSize,
          accountToken,
          strategyTag
        }
      });
    } else {
      return res.status(400).json({
        success: false,
        error: result.error
      });
    }

  } catch (error) {
    console.error('❌ BUY signal error:', error.message);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
}

// ========================================
// 🔴 SELL SIGNAL HANDLER
// ========================================
async function handleSellSignal(accountToken, strategyTag, symbol, quantity, account, res) {
  try {
    console.log(`🔴 Processing SELL signal for ${symbol}`);

    const product = await getProductBySymbol(symbol, account.baseUrl);
    if (!product) {
      return res.status(404).json({
        success: false,
        error: `Symbol ${symbol} not found`
      });
    }

    let orderSize = quantity ? parseInt(quantity) : 1;
    if (orderSize <= 0) orderSize = 1;

    const orderPayload = {
      product_id: product.id,
      side: 'sell',
      order_type: 'market_order',
      size: orderSize
    };

    const result = await placeOrder(orderPayload, account);

    if (result.success) {
      // Track order metadata
      orderMetadata.set(result.order.id, {
        accountToken,
        strategyTag,
        symbol,
        side: 'sell',
        size: orderSize,
        orderId: result.order.id,
        timestamp: new Date()
      });

      // Update position tracking
      const positionKey = getPositionKey(accountToken, strategyTag, symbol, 'sell');
      
      if (strategyPositions.has(positionKey)) {
        const existingPos = strategyPositions.get(positionKey);
        existingPos.size += orderSize;
        existingPos.orderIds.push(result.order.id);
        existingPos.lastUpdated = new Date();
      } else {
        strategyPositions.set(positionKey, {
          accountToken,
          strategyTag,
          symbol,
          side: 'sell',
          size: orderSize,
          orderIds: [result.order.id],
          createdAt: new Date(),
          lastUpdated: new Date()
        });
      }

      // Update strategy tracking
      updateStrategyTracking(accountToken, strategyTag, symbol);

      console.log(`✅ SELL order placed successfully: ${result.order.id}`);

      return res.json({
        success: true,
        message: 'SELL order placed successfully',
        order: {
          orderId: result.order.id,
          symbol,
          side: 'sell',
          size: orderSize,
          accountToken,
          strategyTag
        }
      });
    } else {
      return res.status(400).json({
        success: false,
        error: result.error
      });
    }

  } catch (error) {
    console.error('❌ SELL signal error:', error.message);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
}

// ========================================
// 🔵❌ BUY EXIT SIGNAL HANDLER (PARTIAL SUPPORT)
// ========================================
async function handleBuyExitSignal(accountToken, strategyTag, symbol, exitQuantity, account, res) {
  try {
    console.log(`🔵❌ Processing BUY_EXIT signal for ${symbol}`);

    const buyPositionKey = getPositionKey(accountToken, strategyTag, symbol, 'buy');
    const buyPosition = strategyPositions.get(buyPositionKey);

    if (!buyPosition) {
      console.log('⚠️ No BUY position found to exit');
      return res.json({
        success: true,
        message: 'No BUY position to exit',
        accountToken,
        strategyTag,
        symbol
      });
    }

    const product = await getProductBySymbol(symbol, account.baseUrl);
    if (!product) {
      return res.status(404).json({
        success: false,
        error: `Symbol ${symbol} not found`
      });
    }

    // Determine exit quantity
    let exitSize = exitQuantity ? parseInt(exitQuantity) : buyPosition.size;
    
    // Ensure we don't exit more than we have
    if (exitSize > buyPosition.size) {
      exitSize = buyPosition.size;
    }

    console.log(`   Current BUY position: ${buyPosition.size}`);
    console.log(`   Exiting quantity: ${exitSize}`);

    const closePayload = {
      product_id: product.id,
      side: 'sell',
      order_type: 'market_order',
      size: exitSize,
      reduce_only: true
    };

    const result = await placeOrder(closePayload, account);

    if (result.success) {
      // Update position tracking
      buyPosition.size -= exitSize;
      buyPosition.lastUpdated = new Date();

      // If position fully closed, remove it
      if (buyPosition.size <= 0) {
        strategyPositions.delete(buyPositionKey);
        console.log(`   ✅ BUY position fully closed`);
      } else {
        console.log(`   ✅ Partial BUY exit: ${exitSize} closed, ${buyPosition.size} remaining`);
      }

      return res.json({
        success: true,
        message: 'BUY_EXIT executed successfully',
        exit: {
          orderId: result.order.id,
          symbol,
          side: 'buy_exit',
          exitedSize: exitSize,
          remainingSize: buyPosition.size > 0 ? buyPosition.size : 0,
          accountToken,
          strategyTag
        }
      });
    } else {
      return res.status(400).json({
        success: false,
        error: result.error
      });
    }

  } catch (error) {
    console.error('❌ BUY_EXIT signal error:', error.message);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
}

// ========================================
// 🔴❌ SELL EXIT SIGNAL HANDLER (PARTIAL SUPPORT)
// ========================================
async function handleSellExitSignal(accountToken, strategyTag, symbol, exitQuantity, account, res) {
  try {
    console.log(`🔴❌ Processing SELL_EXIT signal for ${symbol}`);

    const sellPositionKey = getPositionKey(accountToken, strategyTag, symbol, 'sell');
    const sellPosition = strategyPositions.get(sellPositionKey);

    if (!sellPosition) {
      console.log('⚠️ No SELL position found to exit');
      return res.json({
        success: true,
        message: 'No SELL position to exit',
        accountToken,
        strategyTag,
        symbol
      });
    }

    const product = await getProductBySymbol(symbol, account.baseUrl);
    if (!product) {
      return res.status(404).json({
        success: false,
        error: `Symbol ${symbol} not found`
      });
    }

    // Determine exit quantity
    let exitSize = exitQuantity ? parseInt(exitQuantity) : sellPosition.size;
    
    // Ensure we don't exit more than we have
    if (exitSize > sellPosition.size) {
      exitSize = sellPosition.size;
    }

    console.log(`   Current SELL position: ${sellPosition.size}`);
    console.log(`   Exiting quantity: ${exitSize}`);

    const closePayload = {
      product_id: product.id,
      side: 'buy',
      order_type: 'market_order',
      size: exitSize,
      reduce_only: true
    };

    const result = await placeOrder(closePayload, account);

    if (result.success) {
      // Update position tracking
      sellPosition.size -= exitSize;
      sellPosition.lastUpdated = new Date();

      // If position fully closed, remove it
      if (sellPosition.size <= 0) {
        strategyPositions.delete(sellPositionKey);
        console.log(`   ✅ SELL position fully closed`);
      } else {
        console.log(`   ✅ Partial SELL exit: ${exitSize} closed, ${sellPosition.size} remaining`);
      }

      return res.json({
        success: true,
        message: 'SELL_EXIT executed successfully',
        exit: {
          orderId: result.order.id,
          symbol,
          side: 'sell_exit',
          exitedSize: exitSize,
          remainingSize: sellPosition.size > 0 ? sellPosition.size : 0,
          accountToken,
          strategyTag
        }
      });
    } else {
      return res.status(400).json({
        success: false,
        error: result.error
      });
    }

  } catch (error) {
    console.error('❌ SELL_EXIT signal error:', error.message);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
}

// ========================================
// ❌ EXIT ALL SIGNAL HANDLER
// ========================================
async function handleExitAllSignal(accountToken, strategyTag, symbol, account, res) {
  try {
    console.log(`❌ Processing EXIT_ALL signal for ${symbol}`);

    const buyPositionKey = getPositionKey(accountToken, strategyTag, symbol, 'buy');
    const sellPositionKey = getPositionKey(accountToken, strategyTag, symbol, 'sell');

    const buyPosition = strategyPositions.get(buyPositionKey);
    const sellPosition = strategyPositions.get(sellPositionKey);

    if (!buyPosition && !sellPosition) {
      console.log('⚠️ No positions found to exit');
      return res.json({
        success: true,
        message: 'No positions to exit',
        accountToken,
        strategyTag,
        symbol
      });
    }

    const product = await getProductBySymbol(symbol, account.baseUrl);
    if (!product) {
      return res.status(404).json({
        success: false,
        error: `Symbol ${symbol} not found`
      });
    }

    const closedPositions = [];

    // Close BUY position
    if (buyPosition) {
      const closePayload = {
        product_id: product.id,
        side: 'sell',
        order_type: 'market_order',
        size: buyPosition.size,
        reduce_only: true
      };

      const result = await placeOrder(closePayload, account);
      if (result.success) {
        strategyPositions.delete(buyPositionKey);
        closedPositions.push({ 
          side: 'buy', 
          size: buyPosition.size,
          orderId: result.order.id
        });
        console.log(`   ✅ BUY position closed: ${buyPosition.size}`);
      }
    }

    // Close SELL position
    if (sellPosition) {
      const closePayload = {
        product_id: product.id,
        side: 'buy',
        order_type: 'market_order',
        size: sellPosition.size,
        reduce_only: true
      };

      const result = await placeOrder(closePayload, account);
      if (result.success) {
        strategyPositions.delete(sellPositionKey);
        closedPositions.push({ 
          side: 'sell', 
          size: sellPosition.size,
          orderId: result.order.id
        });
        console.log(`   ✅ SELL position closed: ${sellPosition.size}`);
      }
    }

    console.log(`✅ EXIT_ALL completed: ${closedPositions.length} position(s) closed`);

    return res.json({
      success: true,
      message: 'EXIT_ALL signal processed',
      closedPositions,
      accountToken,
      strategyTag,
      symbol
    });

  } catch (error) {
    console.error('❌ EXIT_ALL signal error:', error.message);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
}

// ========================================
// 🔄 STOP AND REVERSE SIGNAL HANDLER
// ========================================
async function handleStopAndReverseSignal(accountToken, strategyTag, symbol, quantity, account, res) {
  try {
    console.log(`🔄 Processing STOP_AND_REVERSE signal for ${symbol}`);

    const buyPositionKey = getPositionKey(accountToken, strategyTag, symbol, 'buy');
    const sellPositionKey = getPositionKey(accountToken, strategyTag, symbol, 'sell');

    const buyPosition = strategyPositions.get(buyPositionKey);
    const sellPosition = strategyPositions.get(sellPositionKey);

    const product = await getProductBySymbol(symbol, account.baseUrl);
    if (!product) {
      return res.status(404).json({
        success: false,
        error: `Symbol ${symbol} not found`
      });
    }

    let orderSize = quantity ? parseInt(quantity) : 1;
    if (orderSize <= 0) orderSize = 1;

    const actions = [];

    // SCENARIO 1: Currently in BUY position → Exit BUY → Enter SELL
    if (buyPosition) {
      console.log(`   📊 Current: BUY position (${buyPosition.size})`);
      console.log(`   🔄 Action: Exit BUY → Enter SELL`);

      // Step 1: Close BUY position
      const closeBuyPayload = {
        product_id: product.id,
        side: 'sell',
        order_type: 'market_order',
        size: buyPosition.size,
        reduce_only: true
      };

      const closeBuyResult = await placeOrder(closeBuyPayload, account);
      if (closeBuyResult.success) {
        strategyPositions.delete(buyPositionKey);
        actions.push({
          action: 'close_buy',
          size: buyPosition.size,
          orderId: closeBuyResult.order.id
        });
        console.log(`   ✅ BUY position closed: ${buyPosition.size}`);
      }

      // Step 2: Open SELL position
      const openSellPayload = {
        product_id: product.id,
        side: 'sell',
        order_type: 'market_order',
        size: orderSize
      };

      const openSellResult = await placeOrder(openSellPayload, account);
      if (openSellResult.success) {
        strategyPositions.set(sellPositionKey, {
          accountToken,
          strategyTag,
          symbol,
          side: 'sell',
          size: orderSize,
          orderIds: [openSellResult.order.id],
          createdAt: new Date(),
          lastUpdated: new Date()
        });
        actions.push({
          action: 'open_sell',
          size: orderSize,
          orderId: openSellResult.order.id
        });
        console.log(`   ✅ SELL position opened: ${orderSize}`);
      }

      updateStrategyTracking(accountToken, strategyTag, symbol);

      return res.json({
        success: true,
        message: 'STOP_AND_REVERSE: BUY → SELL completed',
        actions,
        accountToken,
        strategyTag,
        symbol
      });
    }

    // SCENARIO 2: Currently in SELL position → Exit SELL → Enter BUY
    if (sellPosition) {
      console.log(`   📊 Current: SELL position (${sellPosition.size})`);
      console.log(`   🔄 Action: Exit SELL → Enter BUY`);

      // Step 1: Close SELL position
      const closeSellPayload = {
        product_id: product.id,
        side: 'buy',
        order_type: 'market_order',
        size: sellPosition.size,
        reduce_only: true
      };

      const closeSellResult = await placeOrder(closeSellPayload, account);
      if (closeSellResult.success) {
        strategyPositions.delete(sellPositionKey);
        actions.push({
          action: 'close_sell',
          size: sellPosition.size,
          orderId: closeSellResult.order.id
        });
        console.log(`   ✅ SELL position closed: ${sellPosition.size}`);
      }

      // Step 2: Open BUY position
      const openBuyPayload = {
        product_id: product.id,
        side: 'buy',
        order_type: 'market_order',
        size: orderSize
      };

      const openBuyResult = await placeOrder(openBuyPayload, account);
      if (openBuyResult.success) {
        strategyPositions.set(buyPositionKey, {
          accountToken,
          strategyTag,
          symbol,
          side: 'buy',
          size: orderSize,
          orderIds: [openBuyResult.order.id],
          createdAt: new Date(),
          lastUpdated: new Date()
        });
        actions.push({
          action: 'open_buy',
          size: orderSize,
          orderId: openBuyResult.order.id
        });
        console.log(`   ✅ BUY position opened: ${orderSize}`);
      }

      updateStrategyTracking(accountToken, strategyTag, symbol);

      return res.json({
        success: true,
        message: 'STOP_AND_REVERSE: SELL → BUY completed',
        actions,
        accountToken,
        strategyTag,
        symbol
      });
    }

    // SCENARIO 3: No existing position → Just open BUY
    console.log(`   ⚠️ No existing position found`);
    console.log(`   🔄 Action: Opening BUY position`);

    const openBuyPayload = {
      product_id: product.id,
      side: 'buy',
      order_type: 'market_order',
      size: orderSize
    };

    const openBuyResult = await placeOrder(openBuyPayload, account);
    if (openBuyResult.success) {
      strategyPositions.set(buyPositionKey, {
        accountToken,
        strategyTag,
        symbol,
        side: 'buy',
        size: orderSize,
        orderIds: [openBuyResult.order.id],
        createdAt: new Date(),
        lastUpdated: new Date()
      });
      actions.push({
        action: 'open_buy',
        size: orderSize,
        orderId: openBuyResult.order.id
      });
      console.log(`   ✅ BUY position opened: ${orderSize}`);
    }

    updateStrategyTracking(accountToken, strategyTag, symbol);

    return res.json({
      success: true,
      message: 'STOP_AND_REVERSE: No position → BUY opened',
      actions,
      accountToken,
      strategyTag,
      symbol
    });

  } catch (error) {
    console.error('❌ STOP_AND_REVERSE signal error:', error.message);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
}

// ========================================
// 📜 TRADING ENDPOINTS (Keep existing code)
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

    const closePayload = {
      product_id: parseInt(product_id)
    };

    const payload = JSON.stringify(closePayload);
    const endpoint = '/v2/positions/close_all';
    const headers = getAuthHeaders('POST', endpoint, '', payload, apiKey, apiSecret);

    const response = await axios.post(
      `${baseUrl}${endpoint}`,
      closePayload,
      { headers, timeout: 10000 }
    );

    res.json({
      success: true,
      result: response.data.result
    });
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

// ========================================
// 🧹 CLEANUP & ERROR HANDLING
// ========================================

setInterval(() => {
  const now = new Date();
  const sessionTimeout = 24 * 60 * 60 * 1000;
  
  for (const [sessionId, session] of userSessions.entries()) {
    if (now - session.lastActivity > sessionTimeout) {
      userSessions.delete(sessionId);
      console.log(`🧹 Cleaned up expired session: ${sessionId}`);
    }
  }
}, 60 * 60 * 1000);

app.use((err, req, res, next) => {
  console.error('❌ Server error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: err.message
  });
});

app.listen(PORT, () => {
  console.log('='.repeat(70));
  console.log('🚀 Delta Trading Bridge - PHASE 2 ENHANCED: ALL WEBHOOK TYPES');
  console.log('='.repeat(70));
  console.log(`📡 Server running on: http://localhost:${PORT}`);
  console.log(`🔐 Session-based authentication enabled`);
  console.log(`🏦 Multi-account support with token-based routing`);
  console.log(`🏷️  Strategy-level isolation and tracking`);
  console.log(`📊 TradingView webhook endpoint: /api/webhook/tradingview`);
  console.log('='.repeat(70));
  console.log('✅ SUPPORTED WEBHOOK SIGNALS:');
  console.log('   1. BUY - Open long position');
  console.log('   2. SELL - Open short position');
  console.log('   3. BUY_EXIT - Close long position (full/partial)');
  console.log('   4. SELL_EXIT - Close short position (full/partial)');
  console.log('   5. EXIT - Close all positions');
  console.log('   6. STOP_AND_REVERSE - Reverse position direction');
  console.log('='.repeat(70));
  console.log('');
});
