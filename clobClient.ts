/**
 * Polymarket CLOB REST API Client
 * https://clob.polymarket.com API endpoints for order books, trades, and prices
 */

import crypto from 'crypto';

interface OrderBookEntry {
  price: string;
  size: string;
}

interface OrderBook {
  market: string;
  asset_id: string;
  bids: OrderBookEntry[];
  asks: OrderBookEntry[];
  timestamp: number;
  hash: string;
}

interface Trade {
  id: string;
  market: string;
  asset_id: string;
  side: 'BUY' | 'SELL';
  price: string;
  size: string;
  timestamp: number;
  outcome: string;
  bucket_index: number;
  fee_rate_bps: string;
  taker_order_id: string;
  maker_order_id: string;
}

interface PriceData {
  market: string;
  asset_id: string;
  token_id: string;
  price: number;
  timestamp: number;
}

interface TickSize {
  price: string;
  size: string;
}

export interface ApiCredentials {
  apiKey: string;
  apiSecret: string;
  apiPassphrase: string;
  walletAddress?: string;
}

export class CLOBClient {
  private readonly BASE_URL = 'https://clob.polymarket.com';
  private requestCache: Map<string, { data: any; timestamp: number }> = new Map();
  private readonly CACHE_TTL = 2000; // 2 seconds cache for REST calls
  
  // Support both POLYMARKET_* and BUILDER_* env var naming conventions
  private readonly API_KEY = process.env.POLYMARKET_API_KEY || process.env.BUILDER_API_KEY;
  private readonly SECRET = process.env.POLYMARKET_SECRET || process.env.BUILDER_SECRET;
  private readonly PASSPHRASE = process.env.POLYMARKET_PASSPHRASE || process.env.BUILDER_PASS_PHRASE;
  private readonly WALLET_ADDRESS = process.env.POLYMARKET_WALLET_ADDRESS || process.env.BUILDER_WALLET_ADDRESS;

  /**
   * Generate authentication headers for Polymarket CLOB API
   * Based on: https://docs.polymarket.com/developers/CLOB/authentication
   * @param method HTTP method (GET, POST, etc.)
   * @param path API path
   * @param body Optional request body
   * @param credentials Optional API credentials (uses environment variables if not provided)
   */
  private generateAuthHeaders(
    method: string, 
    path: string, 
    body?: string, 
    credentials?: ApiCredentials
  ): Record<string, string> {
    const apiKey = credentials?.apiKey || this.API_KEY;
    const apiSecret = credentials?.apiSecret || this.SECRET;
    const apiPassphrase = credentials?.apiPassphrase || this.PASSPHRASE;
    const walletAddress = credentials?.walletAddress;

    if (!apiKey || !apiSecret || !apiPassphrase) {
      console.warn('[CLOB Client] API credentials not configured');
      return {};
    }

    // Polymarket uses Unix timestamp in seconds
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const message = timestamp + method + path + (body || '');
    
    // Secret is used as UTF-8 string (not base64-decoded)
    const signature = crypto
      .createHmac('sha256', apiSecret)
      .update(message)
      .digest('base64');

    return {
      'POLY_ADDRESS': walletAddress || this.WALLET_ADDRESS || '',
      'POLY_SIGNATURE': signature,
      'POLY_TIMESTAMP': timestamp,
      'POLY_PASSPHRASE': apiPassphrase,
      'POLY_API_KEY': apiKey,
      'Content-Type': 'application/json',
    };
  }

  /**
   * Get order book for a specific token
   * @param tokenId Token ID to fetch order book for
   * @param credentials Optional API credentials for authenticated requests
   */
  async getOrderBook(tokenId: string, credentials?: ApiCredentials): Promise<OrderBook | null> {
    const walletAddress = credentials?.walletAddress || 'anon';
    const cacheKey = `orderbook:${tokenId}:${walletAddress}`;
    const cached = this.getCached(cacheKey);
    if (cached) return cached;

    try {
      const path = `/book?token_id=${tokenId}`;
      const url = `${this.BASE_URL}${path}`;
      
      // Generate authentication headers with credentials if provided
      const authHeaders = credentials 
        ? this.generateAuthHeaders('GET', path, undefined, credentials)
        : {};
      
      const response = await fetch(url, {
        headers: {
          ...authHeaders,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        if (response.status === 404) {
          console.warn(`[CLOB Client] Order book not found for token ${tokenId}`);
          return null;
        }
        throw new Error(`Failed to fetch order book: ${response.status}`);
      }

      const data = await response.json();

      const orderBook: OrderBook = {
        market: data.market || tokenId,
        asset_id: data.asset_id || tokenId,
        bids: data.bids || [],
        asks: data.asks || [],
        timestamp: data.timestamp || Date.now(),
        hash: data.hash || '',
      };

      this.setCached(cacheKey, orderBook);
      return orderBook;
    } catch (error) {
      console.error(`[CLOB Client] Failed to fetch order book for ${tokenId}:`, error);
      return null;
    }
  }

  /**
   * Get recent trades for a specific token
   * @param tokenId Token ID to fetch trades for
   * @param limit Maximum number of trades to return
   * @param credentials Optional API credentials for authenticated requests
   */
  async getTrades(tokenId: string, limit = 20, credentials?: ApiCredentials): Promise<Trade[]> {
    const walletAddress = credentials?.walletAddress || this.WALLET_ADDRESS || 'anon';
    const cacheKey = `trades:${tokenId}:${limit}:${walletAddress}`;
    const cached = this.getCached(cacheKey);
    if (cached) return cached;

    try {
      const path = `/trades?asset_id=${tokenId}&limit=${limit}`;
      const url = `${this.BASE_URL}${path}`;

      // Always use authentication - either provided credentials or env defaults
      const authHeaders = this.generateAuthHeaders('GET', path, undefined, credentials);
      
      const response = await fetch(url, {
        headers: {
          ...authHeaders,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        if (response.status === 404) {
          console.warn(`[CLOB Client] Trades not found for token ${tokenId}`);
          return [];
        }
        if (response.status === 401) {
          const addrInfo = walletAddress ? `with wallet ${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}` : 'without wallet address';
          console.error(`[CLOB Client] Authentication failed for trades endpoint ${addrInfo}. Status: ${response.status}, Error:`, errorText);
          return [];
        }
        throw new Error(`Failed to fetch trades: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      const trades: Trade[] = Array.isArray(data) ? data : [];

      this.setCached(cacheKey, trades);
      return trades;
    } catch (error) {
      console.error(`[CLOB Client] Failed to fetch trades for ${tokenId}:`, error);
      return [];
    }
  }

  /**
   * Get current price for a token
   * @param tokenId Token ID to fetch price for
   * @param credentials Optional API credentials for authenticated requests
   */
  async getPrice(tokenId: string, credentials?: ApiCredentials): Promise<number | null> {
    const walletAddress = credentials?.walletAddress || 'anon';
    const cacheKey = `price:${tokenId}:${walletAddress}`;
    const cached = this.getCached(cacheKey);
    if (cached !== null && cached !== undefined) return cached;

    try {
      const path = `/price?token_id=${tokenId}`;
      const url = `${this.BASE_URL}${path}`;
      
      // Generate authentication headers with credentials if provided
      const authHeaders = credentials 
        ? this.generateAuthHeaders('GET', path, undefined, credentials)
        : {};
      
      const response = await fetch(url, {
        headers: {
          ...authHeaders,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        // Try getting price from order book instead
        const orderBook = await this.getOrderBook(tokenId, credentials);
        if (orderBook && orderBook.asks.length > 0 && orderBook.bids.length > 0) {
          const midPrice = (parseFloat(orderBook.asks[0].price) + parseFloat(orderBook.bids[0].price)) / 2;
          this.setCached(cacheKey, midPrice);
          return midPrice;
        }
        return null;
      }

      const data = await response.json();
      const price = parseFloat(data.price);

      this.setCached(cacheKey, price);
      return price;
    } catch (error) {
      console.error(`[CLOB Client] Failed to fetch price for ${tokenId}:`, error);
      return null;
    }
  }

  /**
   * Get prices for multiple tokens (batch request)
   * @param tokenIds Array of token IDs to fetch prices for
   * @param credentials Optional API credentials for authenticated requests
   */
  async getPrices(tokenIds: string[], credentials?: ApiCredentials): Promise<Map<string, number>> {
    const prices = new Map<string, number>();

    // Fetch prices in parallel with rate limiting
    const batchSize = 10;
    for (let i = 0; i < tokenIds.length; i += batchSize) {
      const batch = tokenIds.slice(i, i + batchSize);
      const pricePromises = batch.map(async (tokenId) => {
        const price = await this.getPrice(tokenId, credentials);
        if (price !== null) {
          prices.set(tokenId, price);
        }
      });

      await Promise.all(pricePromises);
    }

    return prices;
  }

  /**
   * Get tick size for a market
   */
  async getTickSize(tokenId: string): Promise<TickSize | null> {
    try {
      const url = `${this.BASE_URL}/tick-size?token_id=${tokenId}`;
      const response = await fetch(url);

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      return {
        price: data.price || '0.01',
        size: data.size || '1',
      };
    } catch (error) {
      console.error(`[CLOB Client] Failed to fetch tick size for ${tokenId}:`, error);
      return null;
    }
  }

  /**
   * Get spread for a token (bid-ask spread)
   * @param tokenId Token ID to fetch spread for
   * @param credentials Optional API credentials for authenticated requests
   */
  async getSpread(tokenId: string, credentials?: ApiCredentials): Promise<number | null> {
    const orderBook = await this.getOrderBook(tokenId, credentials);
    if (!orderBook || orderBook.asks.length === 0 || orderBook.bids.length === 0) {
      return null;
    }

    const bestAsk = parseFloat(orderBook.asks[0].price);
    const bestBid = parseFloat(orderBook.bids[0].price);
    const spread = bestAsk - bestBid;

    return spread;
  }

  /**
   * Calculate mid price from order book
   * @param tokenId Token ID to fetch mid price for
   * @param credentials Optional API credentials for authenticated requests
   */
  async getMidPrice(tokenId: string, credentials?: ApiCredentials): Promise<number | null> {
    const orderBook = await this.getOrderBook(tokenId, credentials);
    if (!orderBook || orderBook.asks.length === 0 || orderBook.bids.length === 0) {
      return null;
    }

    const bestAsk = parseFloat(orderBook.asks[0].price);
    const bestBid = parseFloat(orderBook.bids[0].price);
    const midPrice = (bestAsk + bestBid) / 2;

    return midPrice;
  }

  /**
   * Get cached data if still valid
   */
  private getCached(key: string): any {
    const cached = this.requestCache.get(key);
    if (!cached) return null;

    const age = Date.now() - cached.timestamp;
    if (age > this.CACHE_TTL) {
      this.requestCache.delete(key);
      return null;
    }

    return cached.data;
  }

  /**
   * Cache data with timestamp
   */
  private setCached(key: string, data: any): void {
    this.requestCache.set(key, {
      data,
      timestamp: Date.now(),
    });

    // Limit cache size to prevent memory leaks
    if (this.requestCache.size > 1000) {
      // Remove oldest entries
      const entries = Array.from(this.requestCache.entries());
      entries
        .sort((a, b) => a[1].timestamp - b[1].timestamp)
        .slice(0, 500)
        .forEach(([key]) => this.requestCache.delete(key));
    }
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.requestCache.clear();
  }
}

// Singleton instance
export const clobClient = new CLOBClient();
