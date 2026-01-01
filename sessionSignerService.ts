/**
 * Session Signer Service
 * 
 * Manages Polymarket session signers for automated trading.
 * Session signers allow trades without user confirmation on each transaction.
 * 
 * Stand.trade Approach:
 * - Auto-generates a server-side proxy wallet for each user wallet
 * - Derives CLOB credentials from the proxy wallet (not user's wallet)
 * - Proxy wallet can sign trades on behalf of the user
 * - Simple one-click setup - no wallet export required
 * 
 * Security:
 * - Proxy wallet private key is generated deterministically from user's address
 * - API credentials are encrypted before storage
 * - Session keys expire after 30 days
 */

import { ClobClient } from '@polymarket/clob-client';
import { Wallet } from '@ethersproject/wallet';
import crypto from 'crypto';

export interface DerivedApiCredentials {
  apiKey: string;
  apiSecret: string;
  apiPassphrase: string;
}

/**
 * Generate a deterministic proxy wallet for a user's address
 * This creates a consistent session wallet for the same user address
 *
 * Uses HMAC-SHA256 with server secret for deterministic key derivation. 
 *
 * @param userWalletAddress - The user's connected wallet address
 * @returns Ethers Wallet instance for the proxy
 */
export function generateDeterministicProxyWallet(userWalletAddress: string): Wallet {
  const secret = process.env.ENCRYPTION_KEY;
  if (!secret) {
    throw new Error('ENCRYPTION_KEY not configured');
  }
  
  // Generate deterministic private key from user address + secret
  // This ensures same user always gets same proxy wallet
  const hash = crypto
    .createHmac('sha256', secret)
    .update(userWalletAddress.toLowerCase())
    .digest('hex');
  
  return new Wallet('0x' + hash);
}

/**
 * Auto-generate session signer for a user wallet
 * Uses the stored proxy wallet from registration to derive CLOB credentials
 * No wallet export or user interaction required
 *
 * @param userWalletAddress - The user's connected wallet address
 * @param proxyPrivateKey - Optional: private key of the stored proxy wallet (preferred)
 * @returns API credentials for the proxy wallet
 */
export async function autoGenerateSessionCredentials(
  userWalletAddress: string,
  proxyPrivateKey?: string
): Promise<DerivedApiCredentials> {
  // IMPORTANT: Use direct Polymarket URL for API key creation
  // The proxy may not handle auth endpoints correctly, and Polymarket may reject proxied auth requests
  const host = 'https://clob.polymarket.com';
  const chainId = 137; // Polygon mainnet

  console.log(`[SessionSigner] Using CLOB host: ${host}`);

  // Derive CLOB API credentials from the proxy wallet
  const clobClient = new ClobClient(host, chainId, proxyWallet);

  let creds: any;
  try {
    creds = await clobClient.createOrDeriveApiKey();
    // CLOB API may return 'apiKey' or 'key' depending on version
    const apiKey = creds?.apiKey || creds?.key;
    console.log(`[SessionSigner] API credentials response for proxy ${proxyWallet.address}:`, {
      hasApiKey: !!creds?.apiKey,
      hasKey: !!creds?.key,
      resolvedKey: !!apiKey,
      hasSecret: !!creds?.secret,
      hasPassphrase: !!creds?.passphrase,
    });
  } catch (error: any) {
    console.error(`[SessionSigner] Failed to create API key for ${proxyWallet.address}:`, error.message || error);
    // If createOrDeriveApiKey fails, it might return existing credentials
    if (error.message?.includes('Could not create api key') || error.message?.includes('invalid')) {
      throw new Error(`Failed to create CLOB API key for proxy wallet ${proxyWallet.address}. The wallet may need to be registered with Polymarket first. Error: ${error.message}`);
    }
    throw error;
  }

  // CLOB API may return 'apiKey' or 'key' depending on version - handle both
  const apiKey = creds?.apiKey || creds?.key;

  // Verify credentials
  if (!creds || !apiKey || !creds.secret || !creds.passphrase) {
    console.error(`[SessionSigner] Incomplete credentials:`, {
      hasCreds: !!creds,
      apiKey: !!creds?.apiKey,
      key: !!creds?.key,
      secret: !!creds?.secret,
      passphrase: !!creds?.passphrase,
    });
    throw new Error('API credentials creation returned incomplete data');
  }

  // Verify the API key works by making a lightweight test authenticated request
  // Use getApiKeys() instead of getOpenOrders() as it's faster and doesn't require market data
  try {
    const testClient = new ClobClient(
      host,
      chainId,
      proxyWallet,
      {
        key: apiKey,
        secret: creds.secret,
        passphrase: creds.passphrase,
      }
    );
    // Try to get API keys as verification - this is a lightweight call that requires valid API credentials
    // Use a timeout to prevent hanging
    const verificationPromise = testClient.getApiKeys();
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Verification timeout')), 5000)
    );

    await Promise.race([verificationPromise, timeoutPromise]);
    console.log(`[SessionSigner] API key verified successfully for ${proxyWallet.address}`);
  } catch (verifyError: any) {
    // If verification fails with auth error, the credentials are invalid
    if (verifyError.message?.includes('401') || verifyError.message?.includes('unauthorized') || verifyError.message?.includes('invalid signature')) {
      throw new Error(`API key verification failed for ${proxyWallet.address}. The credentials may be invalid. Please try regenerating.`);
    }
    // Timeout or other errors - log but don't fail (credentials might still be valid)
    if (verifyError.message?.includes('timeout')) {
      console.warn(`[SessionSigner] API key verification timed out for ${proxyWallet.address}, but credentials were created. Continuing...`);
    } else {
      console.log(`[SessionSigner] API key verification completed (may have errors, but credentials were created)`);
    }
  }

  return {
    apiKey: apiKey,
    apiSecret: creds.secret,
    apiPassphrase: creds.passphrase,
  };
}

/**
 * Generate HMAC signature for CLOB API request
 * 
 * @param timestamp - Unix timestamp in seconds
 * @param method - HTTP method (GET, POST, etc.)
 * @param path - API path
 * @param body - Request body (if any)
 * @param apiSecret - The API secret for HMAC signing
 * @returns Base64-encoded HMAC-SHA256 signature
 */
export function generateClobSignature(
  timestamp: string,
  method: string,
  path: string,
  body: string | undefined,
  apiSecret: string
): string {
  const crypto = require('crypto');
  const message = timestamp + method + path + (body || '');
  
  return crypto
    .createHmac('sha256', apiSecret)
    .update(message)
    .digest('base64');
}

/**
 * Generate authentication headers for CLOB API request
 * 
 * @param apiKey - The API key
 * @param apiSecret - The API secret
 * @param apiPassphrase - The API passphrase
 * @param method - HTTP method
 * @param path - API path
 * @param body - Request body (if any)
 * @returns Headers object for CLOB API request
 */
export function generateAuthHeaders(
  apiKey: string,
  apiSecret: string,
  apiPassphrase: string,
  method: string,
  path: string,
  body?: string
): Record<string, string> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signature = generateClobSignature(timestamp, method, path, body, apiSecret);
  
  return {
    'POLY_ADDRESS': apiKey,
    'POLY_SIGNATURE': signature,
    'POLY_TIMESTAMP': timestamp,
    'POLY_PASSPHRASE': apiPassphrase,
    'POLY_API_KEY': apiKey,
    'Content-Type': 'application/json',
  };
}
