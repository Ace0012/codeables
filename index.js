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

// Delta Exchange Configuration
const DELTA_BASE_URL = process.env.DELTA_BASE_URL || 'https://cdn-ind.testnet.deltaex.org';
const API_KEY = process.env.DELTA_API_KEY;
const API_SECRET = process.env.DELTA_API_SECRET;

// Validate configuration on startup
if (!API_KEY || !API_SECRET) {
  console.warn('⚠️  WARNING: API_KEY or API_SECRET not configured in .env file');
}

// Generate signature for authenticated requests
function generateSignature(method, endpoint, queryString = '', payload = '') {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signatureData = method + timestamp + endpoint + queryString + payload;
  const signature = crypto
    .createHmac('sha256', API_SECRET)
    .update(signatureData)
    .digest('hex');
  
  return { signature, timestamp };
}

// Create authenticated request headers
function getAuthHeaders(method, endpoint, queryString = '', payload = '') {
  if (!API_KEY || !API_SECRET) {
    throw new Error('API credentials not configured');
  }
  
  const { signature, timestamp } = generateSignature(method, endpoint, queryString, payload);
  
  return {
    'api-key': API_KEY,
    'timestamp': timestamp,
    'signature': signature,
    'Content-Type': 'application/json',
    'User-Agent': 'delta-trading-panel'
  };
}

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    config: {
      baseUrl: DELTA_BASE_URL,
      apiKeyConfigured: !!API_KEY,
      apiSecretConfigured: !!API_SECRET
    }
  });
});

// Get all trading symbols/products
app.get('/api/symbols', async (req, res) => {
  try {
    console.log('Fetching symbols from Delta Exchange...');
    
    const response = await axios.get(`${DELTA_BASE_URL}/v2/products`, {
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
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
    
    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

// Place order
app.post('/api/order', async (req, res) => {
  try {
    console.log('Placing order:', req.body);
    
    const { product_id, side, order_type, size, limit_price } = req.body;

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
    const headers = getAuthHeaders('POST', endpoint, '', payload);

    console.log('Order payload:', orderPayload);

    const response = await axios.post(
      `${DELTA_BASE_URL}${endpoint}`,
      orderPayload,
      { headers, timeout: 10000 }
    );

    console.log('✓ Order placed successfully');

    res.json({
      success: true,
      order: response.data.result
    });
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

// Get positions - FIXED VERSION
app.get('/api/positions', async (req, res) => {
  try {
    console.log('Fetching positions...');
    
    const endpoint = '/v2/positions/margined';
    const queryString = '';
    const headers = getAuthHeaders('GET', endpoint, queryString, '');

    console.log('Request URL:', `${DELTA_BASE_URL}${endpoint}`);
    console.log('Headers:', { ...headers, 'api-key': '***', 'signature': '***' });

    const response = await axios.get(
      `${DELTA_BASE_URL}${endpoint}`,
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
    if (error.response) {
      console.error('Response data:', JSON.stringify(error.response.data, null, 2));
      console.error('Response status:', error.response.status);
    }
    
    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message,
      details: error.response?.data?.error
    });
  }
});

// Close position
app.post('/api/position/close', async (req, res) => {
  try {
    console.log('Closing position:', req.body);
    
    const { product_id } = req.body;

    const closePayload = {
      product_id: parseInt(product_id)
    };

    const payload = JSON.stringify(closePayload);
    const endpoint = '/v2/positions/close_all';
    const headers = getAuthHeaders('POST', endpoint, '', payload);

    const response = await axios.post(
      `${DELTA_BASE_URL}${endpoint}`,
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

// Get order history - FIXED VERSION
app.get('/api/orders/history', async (req, res) => {
  try {
    console.log('Fetching order history...');
    
    const limit = req.query.limit || 20;
    const endpoint = '/v2/orders/history';
    const queryString = `?page_size=${limit}`;
    const headers = getAuthHeaders('GET', endpoint, queryString, '');

    const response = await axios.get(
      `${DELTA_BASE_URL}${endpoint}${queryString}`,
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

// Get account info - FIXED VERSION
app.get('/api/account', async (req, res) => {
  try {
    console.log('Fetching account info...');
    
    const endpoint = '/v2/wallet/balances';
    const queryString = '';
    const headers = getAuthHeaders('GET', endpoint, queryString, '');

    const response = await axios.get(
      `${DELTA_BASE_URL}${endpoint}`,
      { headers, timeout: 10000 }
    );

    console.log('✓ Fetched account info');

    const walletData = response.data.result[0] || {};

    const account = {
      available_balance: parseFloat(walletData.available_balance || 0),
      total_balance: parseFloat(walletData.balance || 0),
      margin_balance: parseFloat(walletData.available_balance || 0),
      initial_margin: parseFloat(walletData.order_margin || 0) + parseFloat(walletData.position_margin || 0),
      maintenance_margin: parseFloat(walletData.position_margin || 0),
      unrealized_pnl: parseFloat(walletData.unrealized_pnl || 0)
    };

    res.json({
      success: true,
      account: account
    });
  } catch (error) {
    console.error('❌ Error fetching account info:', error.message);
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

// Get wallet balances
app.get('/api/wallet', async (req, res) => {
  try {
    console.log('Fetching wallet balances...');
    
    const endpoint = '/v2/wallet/balances';
    const headers = getAuthHeaders('GET', endpoint, '', '');

    const response = await axios.get(
      `${DELTA_BASE_URL}${endpoint}`,
      { headers, timeout: 10000 }
    );

    console.log('✓ Fetched wallet balances');

    res.json({
      success: true,
      balances: response.data.result
    });
  } catch (error) {
    console.error('❌ Error fetching wallet:', error.message);
    if (error.response) {
      console.error('Response data:', JSON.stringify(error.response.data, null, 2));
    }
    
    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

// Get market data for a symbol
app.get('/api/market-data', async (req, res) => {
  try {
    const { symbol } = req.query;
    console.log(`Fetching market data for ${symbol}...`);

    const response = await axios.get(`${DELTA_BASE_URL}/v2/tickers/${symbol}`, {
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
    if (error.response) {
      console.error('Response data:', JSON.stringify(error.response.data, null, 2));
    }
    
    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

// Get product info
app.get('/api/product/:productId', async (req, res) => {
  try {
    const { productId } = req.params;
    console.log(`Fetching product info for ${productId}...`);

    const response = await axios.get(`${DELTA_BASE_URL}/v2/products/${productId}`, {
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
    if (error.response) {
      console.error('Response data:', JSON.stringify(error.response.data, null, 2));
    }
    
    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || error.message
    });
  }
});

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
  console.log('🚀 Delta Trading Panel Backend');
  console.log('='.repeat(60));
  console.log(`📡 Server running on: http://localhost:${PORT}`);
  console.log(`📊 API Base URL: ${DELTA_BASE_URL}`);
  console.log(`🔑 API Key configured: ${API_KEY ? 'Yes ✓' : 'No ✗'}`);
  console.log(`🔐 API Secret configured: ${API_SECRET ? 'Yes ✓' : 'No ✗'}`);
  console.log('='.repeat(60));
  
  if (!API_KEY || !API_SECRET) {
    console.log('');
    console.log('⚠️  WARNING: API credentials not configured!');
    console.log('📝 Please create a .env file with:');
    console.log('   DELTA_API_KEY=your_key_here');
    console.log('   DELTA_API_SECRET=your_secret_here');
    console.log('');
    console.log('🔗 Get API keys from:');
    console.log('   Testnet: https://testnet.delta.exchange/app/account/api-keys');
    console.log('   Production: https://www.delta.exchange/app/account/api-keys');
    console.log('='.repeat(60));
  }
});
