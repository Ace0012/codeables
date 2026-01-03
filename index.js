const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// In-memory session storage (use Redis/Database in production)
const userSessions = new Map();

// Generate signature for authenticated requests
function generateSignature(method, endpoint, queryString = '', payload = '', apiSecret) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signatureData = method + timestamp + endpoint + queryString + payload;
  
  console.log('🔐 Signature Debug:');
  console.log('  Method:', method);
  console.log('  Timestamp:', timestamp);
  console.log('  Endpoint:', endpoint);
  console.log('  Query String:', queryString);
  console.log('  Payload:', payload);
  console.log('  Signature Data:', signatureData);
  
  const signature = crypto
    .createHmac('sha256', apiSecret)
    .update(signatureData)
    .digest('hex');
  
  console.log('  Generated Signature:', signature);
  
  return { signature, timestamp };
}

// Create authenticated request headers
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
    'User-Agent': 'delta-trading-bridge'
  };
}

// Get base URL based on account type
function getBaseUrl(accountType) {
  return accountType === 'testnet' 
    ? 'https://cdn-ind.testnet.deltaex.org'
    : 'https://api.india.delta.exchange';
}

// Middleware to validate session
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

// Helper function to validate order before placing
async function validateOrder(orderData, userSession) {
  const { apiKey, apiSecret, baseUrl } = userSession;
  
  try {
    // Fetch wallet balance
    const walletEndpoint = '/v2/wallet/balances';
    const walletHeaders = getAuthHeaders('GET', walletEndpoint, '', '', apiKey, apiSecret);
    const walletResponse = await axios.get(`${baseUrl}${walletEndpoint}`, { headers: walletHeaders, timeout: 10000 });
    
    const wallet = walletResponse.data.result[0] || {};
    const availableBalance = parseFloat(wallet.available_balance || 0);
    
    // Fetch product info
    const productResponse = await axios.get(`${baseUrl}/v2/products/${orderData.product_id}`, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });
    
    const product = productResponse.data.result;
    
    // Fetch current market price
    const tickerResponse = await axios.get(`${baseUrl}/v2/tickers/${product.symbol}`, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });
    
    const currentPrice = parseFloat(tickerResponse.data.result.mark_price || tickerResponse.data.result.close);
    const orderPrice = orderData.order_type === 'limit_order' ? parseFloat(orderData.limit_price) : currentPrice;
    
    // Calculate required margin
    const contractValue = parseFloat(product.contract_value);
    const notionalValue = orderData.size * contractValue * orderPrice;
    const defaultLeverage = parseFloat(product.default_leverage || 1);
    const requiredMargin = notionalValue / defaultLeverage;
    
    // Add buffer for fees (0.05% taker fee)
    const estimatedFee = notionalValue * 0.0005;
    const totalRequired = requiredMargin + estimatedFee;
    
    console.log('📊 Order Validation:');
    console.log('  Available Balance:', availableBalance);
    console.log('  Required Margin:', requiredMargin);
    console.log('  Estimated Fee:', estimatedFee);
    console.log('  Total Required:', totalRequired);
    console.log('  Notional Value:', notionalValue);
    console.log('  Current Price:', currentPrice);
    console.log('  Order Price:', orderPrice);
    
    return {
      isValid: availableBalance >= totalRequired,
      availableBalance,
      requiredMargin,
      estimatedFee,
      totalRequired,
      notionalValue,
      currentPrice,
      product
    };
  } catch (error) {
    console.error('❌ Validation error:', error.message);
    return {
      isValid: false,
      error: error.message
    };
  }
}

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    activeSessions: userSessions.size
  });
});

// Login endpoint - Validate API credentials and create session
app.post('/api/auth/login', async (req, res) => {
  try {
    const { apiKey, apiSecret, accountType } = req.body;

    console.log('📝 Login Request:');
    console.log('  Account Type:', accountType);
    console.log('  API Key Length:', apiKey?.length);
    console.log('  API Secret Length:', apiSecret?.length);

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

    console.log(`🔄 Attempting login for ${accountType} account...`);

    const baseUrl = getBaseUrl(accountType);
    const endpoint = '/v2/profile';
    
    console.log('🌐 Base URL:', baseUrl);
    console.log('🔗 Full URL:', `${baseUrl}${endpoint}`);
    
    const headers = getAuthHeaders('GET', endpoint, '', '', apiKey, apiSecret);
    
    console.log('📤 Request Headers:', {
      ...headers,
      'api-key': apiKey.substring(0, 10) + '...',
      'signature': headers.signature.substring(0, 10) + '...'
    });

    // Validate credentials by fetching user profile
    const response = await axios.get(
      `${baseUrl}${endpoint}`,
      { 
        headers, 
        timeout: 15000,
        validateStatus: function (status) {
          return status < 500; // Resolve only if status is less than 500
        }
      }
    );

    console.log('📥 Response Status:', response.status);
    console.log('📥 Response Data:', JSON.stringify(response.data, null, 2));

    if (response.status === 200 && response.data.success) {
      // Generate session ID
      const sessionId = crypto.randomBytes(32).toString('hex');
      
      // Store session
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
    
    if (error.response) {
      console.error('Error Response Status:', error.response.status);
      console.error('Error Response Data:', JSON.stringify(error.response.data, null, 2));
      console.error('Error Response Headers:', error.response.headers);
      
      // Check for specific error codes
      if (error.response.data?.error?.code === 'ip_blocked_for_api_key') {
        return res.status(403).json({
          success: false,
          error: 'IP address not whitelisted. Please add your IP address to the API key whitelist on Delta Exchange.',
          code: 'ip_blocked'
        });
      }
      
      if (error.response.status === 401 || error.response.status === 403) {
        return res.status(401).json({
          success: false,
          error: 'Invalid API credentials or insufficient permissions. Please check your API key and secret.',
          details: error.response.data
        });
      }
      
      return res.status(500).json({
        success: false,
        error: error.response.data?.error?.message || 'Authentication failed',
        details: error.response.data
      });
    }
    
    if (error.code === 'ECONNABORTED') {
      return res.status(408).json({
        success: false,
        error: 'Connection timeout. Please check your internet connection and try again.'
      });
    }
    
    res.status(500).json({
      success: false,
      error: error.message || 'An unexpected error occurred'
    });
  }
});

// Logout endpoint
app.post('/api/auth/logout', validateSession, (req, res) => {
  const sessionId = req.headers['x-session-id'];
  userSessions.delete(sessionId);
  
  console.log('👋 User logged out, session deleted:', sessionId);
  
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

// Validate session endpoint
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

// Get all trading symbols/products
app.get('/api/symbols', validateSession, async (req, res) => {
  try {
    console.log('Fetching symbols from Delta Exchange...');
    
    const { baseUrl } = req.userSession;
    
    const response = await axios.get(`${baseUrl}/v2/products`, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });

    console.log(`✓ Fetched ${response.data.result.length} products`);

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

    console.log(`✓ Filtered to ${symbols.length} perpetual futures`);

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

// Place order with validation
app.post('/api/order', validateSession, async (req, res) => {
  try {
    console.log('📝 Placing order:', req.body);
    
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

    // Validate order before placing
    console.log('🔍 Validating order...');
    const validation = await validateOrder(orderPayload, req.userSession);
    
    if (!validation.isValid) {
      if (validation.error) {
        return res.status(400).json({
          success: false,
          error: 'Order validation failed',
          details: validation.error
        });
      }
      
      return res.status(400).json({
        success: false,
        error: 'Insufficient balance for this order',
        validation: {
          availableBalance: validation.availableBalance,
          requiredMargin: validation.requiredMargin,
          estimatedFee: validation.estimatedFee,
          totalRequired: validation.totalRequired,
          shortfall: validation.totalRequired - validation.availableBalance
        }
      });
    }

    console.log('✅ Order validation passed');

    const payload = JSON.stringify(orderPayload);
    const endpoint = '/v2/orders';
    const headers = getAuthHeaders('POST', endpoint, '', payload, apiKey, apiSecret);

    console.log('📤 Sending order to Delta Exchange...');

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
      console.log('✅ Order placed successfully');

      res.json({
        success: true,
        order: response.data.result
      });
    } else {
      console.error('❌ Order placement failed:', response.data);
      
      // Handle specific error codes
      let errorMessage = response.data.error?.message || 'Order placement failed';
      
      if (response.data.error?.code === 'immediate_liquidation') {
        errorMessage = 'Order would cause immediate liquidation. Insufficient margin or balance.';
      } else if (response.data.error?.code === 'insufficient_margin') {
        errorMessage = 'Insufficient margin to place this order.';
      } else if (response.data.error?.code === 'invalid_leverage') {
        errorMessage = 'Invalid leverage for this order.';
      } else if (response.data.error?.code === 'invalid_contract') {
        errorMessage = 'Invalid trading contract or symbol.';
      }
      
      res.status(400).json({
        success: false,
        error: errorMessage,
        code: response.data.error?.code,
        details: response.data.error
      });
    }
  } catch (error) {
    console.error('❌ Error placing order:', error.message);
    if (error.response) {
      console.error('Response data:', JSON.stringify(error.response.data, null, 2));
    }
    
    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message,
      details: error.response?.data?.error
    });
  }
});

// Get positions
app.get('/api/positions', validateSession, async (req, res) => {
  try {
    console.log('Fetching positions...');
    
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const endpoint = '/v2/positions/margined';
    const queryString = '';
    const headers = getAuthHeaders('GET', endpoint, queryString, '', apiKey, apiSecret);

    const response = await axios.get(
      `${baseUrl}${endpoint}`,
      { headers, timeout: 10000 }
    );

    console.log(`✓ Fetched ${response.data.result.length} positions`);

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

    console.log(`✓ Filtered to ${positions.length} active positions`);

    res.json({
      success: true,
      positions: positions
    });
  } catch (error) {
    console.error('❌ Error fetching positions:', error.message);
    
    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message,
      details: error.response?.data?.error
    });
  }
});

// Close position
app.post('/api/position/close', validateSession, async (req, res) => {
  try {
    console.log('Closing position:', req.body);
    
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

    console.log('✓ Position closed successfully');

    res.json({
      success: true,
      result: response.data.result
    });
  } catch (error) {
    console.error('❌ Error closing position:', error.message);
    
    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message,
      details: error.response?.data?.error
    });
  }
});

// Get order history
app.get('/api/orders/history', validateSession, async (req, res) => {
  try {
    console.log('Fetching order history...');
    
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const limit = req.query.limit || 20;
    const endpoint = '/v2/orders/history';
    const queryString = `?page_size=${limit}`;
    const headers = getAuthHeaders('GET', endpoint, queryString, '', apiKey, apiSecret);

    const response = await axios.get(
      `${baseUrl}${endpoint}${queryString}`,
      { headers, timeout: 10000 }
    );

    console.log(`✓ Fetched ${response.data.result.length} orders`);

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
      error: error.response?.data?.error?.message || error.message,
      details: error.response?.data?.error
    });
  }
});

// Get account info
// Get account info - FIXED VERSION
app.get('/api/account', validateSession, async (req, res) => {
  try {
    console.log('Fetching account info...');
    
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const endpoint = '/v2/wallet/balances';
    const queryString = '';
    const headers = getAuthHeaders('GET', endpoint, queryString, '', apiKey, apiSecret);

    const response = await axios.get(
      `${baseUrl}${endpoint}`,
      { headers, timeout: 10000 }
    );

    console.log('✓ Fetched wallet balances');
    console.log('📊 All Wallets:', JSON.stringify(response.data.result, null, 2));

    // Find USDT wallet (most common trading asset)
    // You can also look for BTC or other assets depending on your needs
    let walletData = response.data.result.find(w => w.asset_symbol === 'USDT');
    
    // If no USDT wallet, try USD
    if (!walletData) {
      walletData = response.data.result.find(w => w.asset_symbol === 'USD');
    }
    
    // If still no wallet, use the first one with balance
    if (!walletData) {
      walletData = response.data.result.find(w => parseFloat(w.balance || 0) > 0);
    }
    
    // Fallback to first wallet
    if (!walletData) {
      walletData = response.data.result[0] || {};
    }

    console.log('💰 Selected Wallet:', walletData.asset_symbol, 'Balance:', walletData.balance);

    const account = {
      asset_symbol: walletData.asset_symbol || 'USDT',
      available_balance: parseFloat(walletData.available_balance || 0),
      total_balance: parseFloat(walletData.balance || 0),
      margin_balance: parseFloat(walletData.available_balance || 0),
      initial_margin: parseFloat(walletData.order_margin || 0) + parseFloat(walletData.position_margin || 0),
      maintenance_margin: parseFloat(walletData.position_margin || 0),
      unrealized_pnl: parseFloat(walletData.unrealized_pnl || 0),
      // Include all wallets for reference
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
      error: error.response?.data?.error?.message || error.message,
      details: error.response?.data?.error
    });
  }
});


// Get wallet balances
app.get('/api/wallet', validateSession, async (req, res) => {
  try {
    console.log('Fetching wallet balances...');
    
    const { apiKey, apiSecret, baseUrl } = req.userSession;
    const endpoint = '/v2/wallet/balances';
    const headers = getAuthHeaders('GET', endpoint, '', '', apiKey, apiSecret);

    const response = await axios.get(
      `${baseUrl}${endpoint}`,
      { headers, timeout: 10000 }
    );

    console.log('✓ Fetched wallet balances');

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

// Get market data for a symbol
app.get('/api/market-data', validateSession, async (req, res) => {
  try {
    const { symbol } = req.query;
    const { baseUrl } = req.userSession;
    
    console.log(`Fetching market data for ${symbol}...`);

    const response = await axios.get(`${baseUrl}/v2/tickers/${symbol}`, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });

    console.log(`✓ Fetched market data for ${symbol}`);

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

// Get product info
app.get('/api/product/:productId', validateSession, async (req, res) => {
  try {
    const { productId } = req.params;
    const { baseUrl } = req.userSession;
    
    console.log(`Fetching product info for ${productId}...`);

    const response = await axios.get(`${baseUrl}/v2/products/${productId}`, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 10000
    });

    console.log(`✓ Fetched product info for ${productId}`);

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

// Session cleanup (run every hour)
setInterval(() => {
  const now = new Date();
  const sessionTimeout = 24 * 60 * 60 * 1000; // 24 hours
  
  for (const [sessionId, session] of userSessions.entries()) {
    if (now - session.lastActivity > sessionTimeout) {
      userSessions.delete(sessionId);
      console.log(`🧹 Cleaned up expired session: ${sessionId}`);
    }
  }
}, 60 * 60 * 1000);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Server error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: err.message
  });
});

app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('🚀 Delta Trading Bridge - Multi-User Platform');
  console.log('='.repeat(60));
  console.log(`📡 Server running on: http://localhost:${PORT}`);
  console.log(`🔐 Session-based authentication enabled`);
  console.log(`🌐 Supports both Testnet and Production accounts`);
  console.log('='.repeat(60));
  console.log('');
  console.log('📝 Debug mode enabled - Check console for detailed logs');
  console.log('');
});
