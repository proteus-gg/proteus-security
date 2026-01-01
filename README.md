This repository contains the Proteus cryptographic primitives, wallet integration patterns, and data schemas so users can verify how their keys are encrypted, transactions are signed, and data is stored.

**Core trading logic remains proprietary.**

---

## What You Can Verify

| Concern | Component | What It Proves |
|---------|-----------|----------------|
| Are my keys encrypted properly? | `encryption.ts` | AES-256-GCM with random IV, auth tags |
| Can you access my private keys? | `sessionSignerService.ts` | Keys derived deterministically, encrypted at rest |

---

## 1. Cryptographic Infrastructure

### `server/lib/encryption.ts`

All sensitive data (private keys, API secrets) is encrypted using **AES-256-GCM** before storage.

```typescript
// Algorithm: AES-256-GCM (authenticated encryption)
// IV: 16 bytes, randomly generated per encryption
// Auth Tag: 16 bytes, prevents tampering
// Key: 32 bytes (256 bits) from ENCRYPTION_KEY env var

// Encrypted format: iv:authTag:ciphertext (hex-encoded)
```

**Security properties:**
- **Authenticated encryption**: Detects tampering via auth tag verification
- **Random IV per operation**: Same plaintext produces different ciphertext
- **Key never in codebase**: Loaded from environment variable only
- **Key validation**: Requires exactly 64 hex characters (32 bytes)

**What this means for you:**
- Your private keys and API secrets are never stored in plaintext
- Even if the database is breached, encrypted data is useless without the server's encryption key
- Each encryption operation uses a unique IV, preventing pattern analysis

---

## 2. Session Signer Service

### `server/sessionSignerService.ts`

Manages Polymarket session signers for trading without per-transaction wallet confirmations.

**How it works:**

1. **Deterministic Proxy Wallet Generation**
   ```typescript
   // Your wallet address + server secret = unique proxy wallet
   // HMAC-SHA256 ensures same input always produces same output
   const hash = crypto
     .createHmac('sha256', serverSecret)
     .update(userWalletAddress.toLowerCase())
     .digest('hex');

   return new Wallet('0x' + hash);
   ```

2. **API Credential Derivation**
   - Proxy wallet signs a message to Polymarket CLOB API
   - Polymarket returns API key, secret, passphrase
   - Credentials are encrypted before storage

3. **HMAC Signature for API Requests**
   ```typescript
   // message = timestamp + method + path + body
   // signature = HMAC-SHA256(message, apiSecret) -> base64
   ```

**Security properties:**
- **Deterministic**: Same user address always maps to same proxy wallet
- **Recoverable**: Proxy wallet can be regenerated if database entry is lost
- **Isolated**: Proxy wallet is separate from your main wallet
- **Encrypted storage**: Private key and API secrets encrypted at rest

**What this means for you:**
- Your main wallet private key is never sent to or stored on our servers
- Session signers can only trade on Polymarket, not transfer arbitrary funds
- You can revoke session access by regenerating credentials

---

## 3. Wallet Integration

Centralized wallet state management using Privy authentication.

**Authentication flow:**

1. User connects wallet via Privy (MetaMask, WalletConnect, etc.)
2. Privy issues JWT access token
3. Token sent to backend with each request
4. Backend validates token before any operation

**Key security features:**

```typescript
// Wallet address extracted from Privy, not user input
const externalWallet = wallets.find((w) => w.walletClientType !== 'privy');
const embeddedWallet = wallets.find((w) => w.walletClientType === 'privy');
const connectedWallet = externalWallet || embeddedWallet;

// Registration requires valid Privy token
const accessToken = await getAccessToken();
const response = await fetch('/api/auth/register', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});
```

**What this means for you:**
- We cannot impersonate your wallet without your Privy session
- Wallet address comes from cryptographic verification, not user claims
- Logout clears all session state

---

## 4. Safe Wallet Management

Gnosis Safe (multi-sig) wallet deployment and management for trading.

**Gasless operations** powered by Polymarket Builder Relayer:
- Safe wallet deployment
- USDC approval for trading
- CTF (Conditional Token Framework) operations

**What this means for you:**
- Your trading wallet is a Gnosis Safe (battle-tested smart contract)
- All transactions go through the Safe's security model
- Gasless = Polymarket pays gas, you don't need MATIC

---

## 5. API Client (CLOB)

### `server/clobClient.ts`

REST API wrapper for Polymarket's Central Limit Order Book.

**Authentication pattern:**

```typescript
// Polymarket L2 Authentication Headers
{
  'POLY_ADDRESS': walletAddress,      // Your trading address
  'POLY_SIGNATURE': hmacSignature,    // HMAC-SHA256 of request
  'POLY_TIMESTAMP': unixTimestamp,    // Replay attack prevention
  'POLY_PASSPHRASE': apiPassphrase,   // Additional auth factor
  'POLY_API_KEY': apiKey,             // Your API key
}
```

**Security properties:**
- **HMAC signatures**: Each request is signed, preventing tampering
- **Timestamps**: Prevents replay attacks (requests expire)
- **No credentials in URLs**: All auth in headers
- **Response caching**: 2-second TTL, prevents credential over-exposure

---

## 6. Data Schemas

Zod validation schemas defining what data we store and validate.

**User data stored:**

| Table | Fields | Encryption |
|-------|--------|------------|
| `users` | id, wallet_address | None (public) |
| `profiles` | username, display_name, bio | None (public) |
| `session_signers` | wallet_address, api_key | API secret & passphrase encrypted |
| `proxy_wallets` | address, private_key | Private key encrypted |
| `positions` | market_id, size, entry_price | None (trading data) |
| `trade_history` | market_id, side, price, size | None (trading data) |

**Sensitive fields are always encrypted:**

```typescript
export const insertSessionSignerSchema = z.object({
  walletAddress: z.string(),
  apiKey: z.string(),
  encryptedApiSecret: z.string(),      // <-- Encrypted
  encryptedApiPassphrase: z.string(),  // <-- Encrypted
  privateKeyEncrypted: z.string().optional(), // <-- Encrypted
});
```

---

## 7. What We Don't Store

- Your main wallet private key
- Wallet seed phrases
- Passwords (we use wallet-based auth)
- Unencrypted API secrets
- Raw transaction signing keys

---

## 8. Third-Party Dependencies

| Service | Purpose | Data Shared |
|---------|---------|-------------|
| **Privy** | Wallet authentication | Wallet address, email (optional) |
| **Supabase** | Database | Encrypted credentials, trading data |
| **Polymarket** | Trading execution | Orders, positions, API credentials |
| **Polygon** | Blockchain | Transaction signatures |


---

## File Reference

```
server/
├── lib/
│   └── encryption.ts          # AES-256-GCM encryption utilities
├── sessionSignerService.ts    # Proxy wallet & API credential management
└── clobClient.ts              # Polymarket API client with HMAC auth

client/src/
├── contexts/
│   └── WalletContext.tsx      # Privy wallet state management
└── components/
    └── SafeWalletManager.tsx  # Gnosis Safe deployment UI

shared/
└── schema.ts                  # Zod validation schemas (data model)
```

---

## Verify Yourself

Clone this repo and audit the code. Key things to check:

1. **Encryption**: Is AES-256-GCM properly implemented?
2. **Key derivation**: Is HMAC-SHA256 used correctly for proxy wallets?
3. **No hardcoded secrets**: Are all sensitive values from env vars?
4. **Auth validation**: Is Privy token checked on every protected route?
5. **Encrypted storage**: Are sensitive fields marked as encrypted in schema?


---

## Contact

Email: team@proteus.gg 
X: @proteusgg


