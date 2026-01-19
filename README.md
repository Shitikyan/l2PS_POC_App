# L2PS Wallet Connect POC

A React + Vite + TypeScript application for testing L2PS (Layer 2 Private System) flows with Wallet Connect (via Demos SDK).

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the development server:
   ```bash
   npm run dev
   ```

3. Open http://localhost:5173

## Usage

1. **Connect Wallet**:
   - Enter a 24-word mnemonic or click "Generate New".
   - Click "Connect" to authenticate with the Demos Node.

2. **Configure L2PS**:
   - **Network UID**: Default is `testnet_l2ps_001`.
   - **AES Key**: Enter the 64-character hex key for the L2PS network.
   - **IV**: Enter the 32-character hex IV.
   - *Note: You can find these in `data/l2ps/<uid>/config.json` or `private_key.txt`/`iv.txt` on your node.*

3. **Send Transactions**:
   - Enter a message payload.
   - Set the number of transactions to batched.
   - Click "Send L2 Batch Transaction".
   - Watch the logs for status updates (Encryption -> Broadcasting -> Confirmation).

## Features

- **Wallet Management**: Generate/Import Ed25519 wallets.
- **L2PS Encryption**: Client-side AES-256-GCM encryption of transactions.
- **Batching**: automated batch sending simulation.
- **Logs**: Real-time status updates and hash tracking.
