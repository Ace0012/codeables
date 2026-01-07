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
// 🔐 PHASE 2: MULTI-ACCOUNT DATA STRUCTURES
// ========================================

// User sessions (existing)
const userSessions = new Map();

// NEW: Account storage
// Structure: Map<accountToken, accountData>
const deltaAccounts = new Map();

// NEW: Strategy tracking
// Structure: Map<accountToken, Map<strategyTag, strategyData>>
const accountStrategies = new Map();

// NEW: Position tracking
// Structure: Map<positionKey, positionData>
// positionKey = `${accountToken}:${strategyTag}:${symbol}:${side}`
const strategyPositions = new Map();

// NEW: Order tracking
// Structure: Map<orderId, orderMetadata>
const orderMetadata = new Map();

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
    'User-Agent': 'delta-trading-bridge-v2'
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

// NEW: Generate unique account token
function generateAccountToken() {
  const prefix = 'ACC';
  const randomPart = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}_${randomPart}`;
}

// NEW: Generate position key
function getPositionKey(accountToken, strategyTag, symbol, side) {
  return `${accountToken}:${strategyTag}:${symbol}:${side}`;
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
    activePositions: strategyPositions.size
  });
});

// ========================================
// 🔐 AUTHENTICATION ENDPOINTS (EXISTING)
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
      
      userSessions.set(sessionId, {
        apiKey,
        apiSecret,
        accountType,
        baseUrl,
        userInfo: response.data.result,
        createdAt: new Date(),
        lastActivity: new Date()
      });

      console.log(`✅ Login successful for user: ${response.data.result.email}`);

      res.json({
        success: true,
        sessionId,
        userInfo: {
          email: response.data.result.email,
          accountName: response.data.result.account_name,
          accountType,
          marginMode: response.data.result.margin_mode
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
      marginMode: req.userSession.userInfo.margin_mode
    }
  });
});

// ========================================
// 🏦 PHASE 2: ACCOUNT MANAGEMENT ENDPOINTS
// ========================================

// Add new Delta Exchange account
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

    // Validate credentials
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

    // Generate unique account token
    const accountToken = generateAccountToken();

    // Store account data
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
    console.log(`   Label: ${accountData.accountLabel}`);
    console.log(`   Email: ${accountData.userEmail}`);

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

// Get all accounts for current user
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

// Delete account
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

    // Clean up all related data
    deltaAccounts.delete(accountToken);
    accountStrategies.delete(accountToken);
    
    // Remove all positions for this account
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

// ========================================
// 📡 PHASE 2: TRADINGVIEW WEBHOOK ENDPOINT
// ========================================

app.post('/api/webhook/tradingview', async (req, res) => {
  try {
    const payload = req.body;
    
    console.log('📡 TradingView Webhook Received:');
    console.log(JSON.stringify(payload, null, 2));

    // Validate required fields
    const { account_token, strategy_tag, signal, symbol, quantity } = payload;

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

    // Update last used timestamp
    account.lastUsed = new Date();

    // Normalize signal
    const normalizedSignal = signal.toUpperCase();

    // Handle EXIT signal
    if (normalizedSignal === 'EXIT' || normalizedSignal === 'CLOSE') {
      return await handleExitSignal(account_token, strategy_tag, symbol, res);
    }

    // Handle BUY/SELL signal
    if (normalizedSignal === 'BUY' || normalizedSignal === 'SELL') {
      return await handleTradeSignal(account_token, strategy_tag, normalizedSignal, symbol, quantity, account, res);
    }

    return res.status(400).json({
      success: false,
      error: 'Invalid signal type. Must be BUY, SELL, or EXIT'
    });

  } catch (error) {
    console.error('❌ Webhook error:', error.message);
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ========================================
// 🔄 SIGNAL HANDLERS
// ========================================

async function handleTradeSignal(accountToken, strategyTag, signal, symbol, quantity, account, res) {
  try {
    console.log(`🔄 Processing ${signal} signal for ${symbol}`);
    console.log(`   Account: ${account.accountLabel}`);
    console.log(`   Strategy: ${strategyTag}`);

    // Get product ID for symbol
    const productsResponse = await axios.get(`${account.baseUrl}/v2/products`, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });

    const product = productsResponse.data.result.find(p => p.symbol === symbol);
    
    if (!product) {
      return res.status(404).json({
        success: false,
        error: `Symbol ${symbol} not found`
      });
    }

    // Determine order size
    let orderSize = quantity ? parseInt(quantity) : 1;
    if (orderSize <= 0) orderSize = 1;

    // Place order
    const orderPayload = {
      product_id: product.id,
      side: signal.toLowerCase(),
      order_type: 'market_order',
      size: orderSize
    };

    const payload = JSON.stringify(orderPayload);
    const endpoint = '/v2/orders';
    const headers = getAuthHeaders('POST', endpoint, '', payload, account.apiKey, account.apiSecret);

    const orderResponse = await axios.post(
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

    if (orderResponse.status === 200 && orderResponse.data.success) {
      const order = orderResponse.data.result;
      
      // Store order metadata
      orderMetadata.set(order.id, {
        accountToken,
        strategyTag,
        symbol,
        side: signal.toLowerCase(),
        size: orderSize,
        orderId: order.id,
        timestamp: new Date()
      });

      // Track position
      const positionKey = getPositionKey(accountToken, strategyTag, symbol, signal.toLowerCase());
      
      if (strategyPositions.has(positionKey)) {
        // Update existing position
        const existingPos = strategyPositions.get(positionKey);
        existingPos.size += orderSize;
        existingPos.orderIds.push(order.id);
        existingPos.lastUpdated = new Date();
      } else {
        // Create new position
        strategyPositions.set(positionKey, {
          accountToken,
          strategyTag,
          symbol,
          side: signal.toLowerCase(),
          size: orderSize,
          orderIds: [order.id],
          createdAt: new Date(),
          lastUpdated: new Date()
        });
      }

      // Track strategy
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

      console.log(`✅ Order placed successfully: ${order.id}`);
      console.log(`   Position Key: ${positionKey}`);

      return res.json({
        success: true,
        message: `${signal} order placed successfully`,
        order: {
          orderId: order.id,
          symbol,
          side: signal.toLowerCase(),
          size: orderSize,
          accountToken,
          strategyTag
        }
      });
    } else {
      console.error('❌ Order placement failed:', orderResponse.data);
      
      return res.status(400).json({
        success: false,
        error: orderResponse.data.error?.message || 'Order placement failed'
      });
    }

  } catch (error) {
    console.error('❌ Trade signal error:', error.message);
    
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
}

async function handleExitSignal(accountToken, strategyTag, symbol, res) {
  try {
    console.log(`🚪 Processing EXIT signal`);
    console.log(`   Account Token: ${accountToken}`);
    console.log(`   Strategy Tag: ${strategyTag}`);
    console.log(`   Symbol: ${symbol}`);

    const account = deltaAccounts.get(accountToken);

    // Find matching positions
    const buyPositionKey = getPositionKey(accountToken, strategyTag, symbol, 'buy');
    const sellPositionKey = getPositionKey(accountToken, strategyTag, symbol, 'sell');

    const buyPosition = strategyPositions.get(buyPositionKey);
    const sellPosition = strategyPositions.get(sellPositionKey);

    if (!buyPosition && !sellPosition) {
      console.log('⚠️ No matching positions found for exit');
      return res.json({
        success: true,
        message: 'No matching positions to exit',
        accountToken,
        strategyTag,
        symbol
      });
    }

    const closedPositions = [];

    // Close buy position
    if (buyPosition) {
      console.log(`   Closing BUY position: ${buyPosition.size} contracts`);
      
      const closePayload = {
        product_id: await getProductId(symbol, account.baseUrl),
        side: 'sell',
        order_type: 'market_order',
        size: buyPosition.size,
        reduce_only: true
      };

      const result = await executeCloseOrder(closePayload, account);
      if (result.success) {
        strategyPositions.delete(buyPositionKey);
        closedPositions.push({ side: 'buy', size: buyPosition.size });
      }
    }

    // Close sell position
    if (sellPosition) {
      console.log(`   Closing SELL position: ${sellPosition.size} contracts`);
      
      const closePayload = {
        product_id: await getProductId(symbol, account.baseUrl),
        side: 'buy',
        order_type: 'market_order',
        size: sellPosition.size,
        reduce_only: true
      };

      const result = await executeCloseOrder(closePayload, account);
      if (result.success) {
        strategyPositions.delete(sellPositionKey);
        closedPositions.push({ side: 'sell', size: sellPosition.size });
      }
    }

    console.log(`✅ Exit completed: ${closedPositions.length} position(s) closed`);

    return res.json({
      success: true,
      message: 'Exit signal processed',
      closedPositions,
      accountToken,
      strategyTag,
      symbol
    });

  } catch (error) {
    console.error('❌ Exit signal error:', error.message);
    
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
}

async function getProductId(symbol, baseUrl) {
  const response = await axios.get(`${baseUrl}/v2/products`, {
    headers: { 'Content-Type': 'application/json' },
    timeout: 10000
  });

  const product = response.data.result.find(p => p.symbol === symbol);
  return product ? product.id : null;
}

async function executeCloseOrder(orderPayload, account) {
  try {
    const payload = JSON.stringify(orderPayload);
    const endpoint = '/v2/orders';
    const headers = getAuthHeaders('POST', endpoint, '', payload, account.apiKey, account.apiSecret);

    const response = await axios.post(
      `${account.baseUrl}${endpoint}`,
      orderPayload,
      { headers, timeout: 10000 }
    );

    return { success: response.data.success, data: response.data };
  } catch (error) {
    console.error('❌ Close order error:', error.message);
    return { success: false, error: error.message };
  }
}

// ========================================
// 📊 MONITORING ENDPOINTS
// ========================================

// Get all strategies for an account
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

// Get all positions for an account
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

// Get system statistics
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
// 📜 EXISTING ENDPOINTS (PHASE 1)
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
  console.log('🚀 Delta Trading Bridge - PHASE 2: MULTI-ACCOUNT SYSTEM');
  console.log('='.repeat(70));
  console.log(`📡 Server running on: http://localhost:${PORT}`);
  console.log(`🔐 Session-based authentication enabled`);
  console.log(`🏦 Multi-account support with token-based routing`);
  console.log(`🏷️  Strategy-level isolation and tracking`);
  console.log(`📊 TradingView webhook endpoint: /api/webhook/tradingview`);
  console.log('='.repeat(70));
  console.log('');
});
