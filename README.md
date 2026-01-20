# L2PS Wallet Connect POC

A React + Vite + TypeScript application for testing L2PS (Layer 2 Privacy Subnets) transaction flows and comparing them with standard L1 transactions.

## Quick Start

```bash
cd docs/poc-app
npm install
npm run dev
# Open http://localhost:5173
```

## 🔐 1. Keys Handling & Environment

L2PS transactions are **encrypted client-side** before they ever leave the wallet. This is why the POC needs `AES Key` and `IV`.

### Configuration
Keys can be configured via `.env` file or directly in the UI ("Advanced Settings").

**Recommended `.env` setup:**
```bash
# .env in docs/poc-app/
VITE_NODE_URL="http://127.0.0.1:53550"
VITE_L2PS_UID="testnet_l2ps_001"
VITE_L2PS_AES_KEY="b9346..." # 64 hex chars
VITE_L2PS_IV="f5405..."      # 32 hex chars
```

### 🔑 How to generate keys?
You can generate secure random keys using `openssl`:

```bash
# Generate 256-bit AES Key (64 hex characters)
openssl rand -hex 32

# Generate 128-bit IV (32 hex characters)
openssl rand -hex 16
```

### ⚠️ Critical Requirement: Matching Keys
Since L2PS uses symmetric encryption, **the keys on the Client (POC) MUST match the keys on the Node.**

- **Client Keys**: Configured in `.env` or UI settings.
- **Node Keys**: Located in `data/l2ps/<uid>/` directory on the server.
  - Key: `data/l2ps/testnet_l2ps_001/private_key.txt`
  - IV: `data/l2ps/testnet_l2ps_001/iv.txt`

If these dont match, the node will fail to decrypt your transactions and they will be rejected.

### Why these keys?
- **L2PS UID**: Identifies which private network you are transacting on.
- **AES Key & IV**: Shared symmetric keys known only to participants of this specific L2PS network.
- **Security Note**: In a real wallet, these would be securely imported via a QR code or secure channel, never hardcoded.

---

## 🔌 2. Connection Interface

The app offers a simple way to simulate a wallet connection:

1.  **Generate New**: Creates a fresh BIP39 mnemonic (24 words).
2.  **Connect Wallet**:
    - Derives the `Ed25519` private/public key pair from the mnemonic.
    - Connects to the Demos Node (via WebSocket/HTTP).
    - Fetches initial balance and publicly available data.

---

## 💸 3. Sending Transactions: L1 vs L2PS

The "Send" tab allows toggling between two distinct modes:

### **L1 Mode (Public)**  📤
- **What it is**: Standard blockchain transaction.
- **Process**:
    1.  Build transaction.
    2.  Sign with wallet.
    3.  Broadcast to network.
- **Visibility**: Alice sends 5 coins to Bob. **Everyone** on the network sees "Alice -> Bob: 5 coins".

### **L2PS Mode (Private)** 🔒
- **What it is**: Encrypted transaction within a private subnet.
- **Process**:
    1.  Build "Inner" transaction (Alice -> Bob: 5 coins).
    2.  **Encrypt** the inner transaction locally using `AES Key` + `IV`.
    3.  Wrap it in an "Outer" transaction (Type: `l2ps`, To: `L2PS_UID`).
    4.  Sign and broadcast.
- **Visibility**:
    - **Public Network**: Sees "Alice sent encrypted blob to L2PS Network". **Amount and Recipient are hidden.**
    - **L2PS Nodes**: Can decrypt and validte.
    - **Validators**: Receive only a hash of the transaction for ordering (Proof of History), not the content.

---

## 📜 4. Transaction History

The "History" tab combines both worlds but highlights a critical difference in data access.

### **L1 History**
- **Endpoint**: `getTransactionHistory`
- **Access**: **Public**.
- **Behavior**: You can request the history of *any* address. The node responds immediately with all plain-text transactions.

### **L2PS History** (The "Private" Part)
- **Endpoint**: `getL2PSAccountTransactions`
- **Access**: **Restricted (Authenticated)**.
- **Mechanism**:
    1.  To fetch history, the wallet **must sign** a request: `getL2PSHistory:{address}:{timestamp}`.
    2.  The node verifies the signature matches the address.
    3.  **If signature fails**: Access Denied (403).
    4.  **If success**: Node returns the encrypted transaction history for *that specific user*.
- **Implication**: Use A cannot see User B's L2PS history because User A cannot sign a request on behalf of User B.

---

## Architecture Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| **Client Encryption** | ✅ Ready | `utils/l2ps.ts` handles AES encryption |
| **L2PS Node Decryption** | ✅ Ready | `handleL2PS.ts` decrypts incoming txs |
| **GCR Edits** | ✅ Ready | State changes calculated and stored |
| **Mempool** | ✅ Ready | Separate `l2ps_mempool` table |
| **Hash Service** | ✅ Ready | `L2PSHashService` runs every 5s |
| **Consensus** | ✅ Ready | `L2PSConsensus` applies changes per block |
| **Mempool Sync** | ✅ Ready | `L2PSConcurrentSync.ts` handles p2p sync |
| **DTR Routing** | ✅ Ready | Relay of hashes to validators enabled |
| **History API** | ✅ Ready | Authenticated endpoint implemented |

## Files Structure

```
poc-app/
├── src/
│   ├── App.tsx          # Main Logic (Keys, Sync, History)
│   ├── utils/
│   │   └── l2ps.ts      # Encryption & Tx Building
│   └── index.css        # Styling
├── .env                 # Configuration
└── package.json
```
