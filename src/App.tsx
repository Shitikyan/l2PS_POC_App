
import { useState, useEffect, useCallback } from 'react'
import { Demos } from "@kynesyslabs/demosdk/websdk"
import * as bip39 from "bip39"
import {
  buildInnerTransaction,
  buildL2PSTransaction,
  createL2PSInstance,
  normalizeHex,
} from './utils/l2ps'
import type { TxPayload, L2PSEncryptedPayload } from './utils/l2ps'
import './index.css'

// Default constants
// Default constants
const DEFAULT_NODE_URL = import.meta.env.VITE_NODE_URL || "http://127.0.0.1:53550"
const DEFAULT_L2PS_UID = import.meta.env.VITE_L2PS_UID || "testnet_l2ps_001"
// Keys should come from env or user input
const DEFAULT_AES_KEY = import.meta.env.VITE_L2PS_AES_KEY || "b9346ff30a8202cd46caa7b4b0142bfc727c99cc0f8667580af945b493038055"
const DEFAULT_IV = import.meta.env.VITE_L2PS_IV || "f5405674114eb2adea5774d36b701a6d"

// Transaction status type
interface TxHistoryItem {
  hash: string;
  outerHash?: string;
  l1BatchHash?: string;
  timestamp: number;
  type: 'l1' | 'l2ps';
  amount?: number;
  status: 'pending' | 'in_mempool' | 'confirmed' | 'failed';
  message?: string;
  from?: string;
  to?: string;
  l1_block_number?: number;
}

function App() {
  // Wallet State
  const [mnemonic, setMnemonic] = useState<string>('')
  const [address, setAddress] = useState<string>('')
  const [balance, setBalance] = useState<string>('0')
  const [isConnected, setIsConnected] = useState<boolean>(false)
  const [demos, setDemos] = useState<Demos | null>(null)

  // Configuration State
  const [mode, setMode] = useState<'l1' | 'l2ps'>('l2ps')
  const [l2psUid, setL2psUid] = useState<string>(DEFAULT_L2PS_UID)
  const [aesKey, setAesKey] = useState<string>(DEFAULT_AES_KEY)
  const [iv, setIv] = useState<string>(DEFAULT_IV)
  const [nodeUrl, setNodeUrl] = useState<string>(DEFAULT_NODE_URL)
  const [showSettings, setShowSettings] = useState<boolean>(false)

  // Transaction State
  const [recipient, setRecipient] = useState<string>('')
  const [amount, setAmount] = useState<string>('0')
  const [txCount, setTxCount] = useState<number>(1)
  const [txMessage, setTxMessage] = useState<string>('Hello L2PS')
  const [logs, setLogs] = useState<string[]>([])
  const [sending, setSending] = useState<boolean>(false)

  // History & L2PS Status
  const [l1History, setL1History] = useState<TxHistoryItem[]>([])
  const [l2psHistory, setL2psHistory] = useState<TxHistoryItem[]>([])
  const [history, setHistory] = useState<TxHistoryItem[]>([])
  const [revealedTxs, setRevealedTxs] = useState<Set<string>>(new Set())
  const [l2psMempoolInfo, setL2psMempoolInfo] = useState<any>(null)
  const [activeTab, setActiveTab] = useState<'send' | 'history' | 'learn'>('send')
  const [historyFilter, setHistoryFilter] = useState<'all' | 'l2ps' | 'l1'>('all')

  // Demo states for Learn tab
  const [demoLoading, setDemoLoading] = useState<boolean>(false)
  const [demoResult, setDemoResult] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null)

  // Combine history whenever L1 or L2PS history changes, deduplicate by hash
  useEffect(() => {
    // Create a map to deduplicate - L2PS takes priority over L1
    const txMap = new Map<string, TxHistoryItem>()

    // Add L1 first (lower priority)
    for (const tx of l1History) {
      if (tx.hash) txMap.set(tx.hash, tx)
    }

    // Add L2PS (higher priority - will overwrite L1 if same hash)
    for (const tx of l2psHistory) {
      if (tx.hash) txMap.set(tx.hash, tx)
    }

    // Convert back to array and sort by timestamp descending
    const combined = Array.from(txMap.values()).sort((a, b) => b.timestamp - a.timestamp)
    setHistory(combined)

    console.log(`[History] Combined: ${l1History.length} L1 + ${l2psHistory.length} L2PS = ${combined.length} unique`)
  }, [l1History, l2psHistory])

  const addLog = (msg: string) => {
    setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev])
  }

  const generateMnemonic = () => {
    const newMnemonic = bip39.generateMnemonic(256)
    setMnemonic(newMnemonic)
    addLog("Generated new 24-word mnemonic")
  }

  // Proper balance fetching using SDK's rpcCall -> nodeCall
  const fetchBalance = useCallback(async (demosInstance: Demos, addr: string) => {
    try {
      // Remove 0x prefix if present for consistency with DB
      const cleanAddr = addr.startsWith('0x') ? addr : `0x${addr}`

      addLog(`Fetching balance for: ${cleanAddr}`)
      console.log("[Balance] Fetching for address:", cleanAddr)

      // Use demos.rpcCall with nodeCall method to get address info
      // SDK expects { method, params[] } format
      const response = await demosInstance.rpcCall({
        method: "nodeCall",
        params: [{
          message: "getAddressInfo",
          data: { address: cleanAddr },
          muid: `balance_${Date.now()}`
        }]
      }, false) // false = not authenticated

      console.log("[Balance] Full response:", JSON.stringify(response, null, 2))
      addLog(`RPC Response: ${JSON.stringify(response?.result)}`)

      if (response?.result === 200 && response?.response) {
        const info = response.response as any
        console.log("[Balance] Info object:", info)

        // Balance could be in different formats - try multiple field names
        // bigint from DB might come as string
        const bal = info.balance ?? info.nativeBalance ?? info.amount ?? 0
        const balStr = typeof bal === 'bigint' ? bal.toString() : String(bal)

        setBalance(balStr)
        addLog(`Balance: ${balStr} DMS`)
      } else {
        addLog(`Balance fetch failed: result=${response?.result}`)
        console.log("[Balance] Failed response:", response)
      }
    } catch (e: any) {
      console.error("Failed to fetch balance", e)
      addLog(`Balance fetch error: ${e.message || 'Unknown'}`)
    }
  }, [])

  // Fetch L2PS mempool status
  const fetchL2PSMempoolInfo = useCallback(async (demosInstance: Demos) => {
    try {
      const response = await demosInstance.rpcCall({
        method: "nodeCall",
        params: [{
          message: "getL2PSMempoolInfo",
          data: { l2psUid: l2psUid },
          muid: `l2ps_info_${Date.now()}`
        }]
      }, false)

      if (response?.result === 200 && response?.response) {
        setL2psMempoolInfo(response.response)
      }
    } catch (e) {
      console.error("Failed to fetch L2PS mempool info", e)
    }
  }, [l2psUid])

  // Fetch L2PS transactions for current account (using new endpoint with signature auth)
  const fetchL2PSTransactions = useCallback(async (demosInstance: Demos, addr: string) => {
    try {
      // Create message to sign for authentication
      const timestamp = Date.now().toString()
      const messageToSign = `getL2PSHistory:${addr}:${timestamp}`

      // Sign the message using the SDK's signMessage method
      let signature: string
      try {
        const signResult = await demosInstance.signMessage(messageToSign)
        // signMessage returns { type: SigningAlgorithm, data: string }
        signature = typeof signResult === 'string' ? signResult : signResult.data
      } catch (signErr) {
        console.error("[L2PS History] Failed to sign message:", signErr)
        addLog("Auth error: Could not sign history request")
        return
      }

      const response = await demosInstance.rpcCall({
        method: "nodeCall",
        params: [{
          message: "getL2PSAccountTransactions",
          data: {
            l2psUid: l2psUid,
            address: addr,
            timestamp: timestamp,
            signature: signature,
            limit: 50
          },
          muid: `l2ps_account_txs_${Date.now()}`
        }]
      }, false)

      console.log("[L2PS History] Response:", response)

      if (response?.result === 401) {
        // Auth required - this shouldn't happen if we signed correctly
        addLog("History auth failed: " + (response?.response || "Unknown"))
        return
      }

      if (response?.result === 403) {
        addLog("Access denied: Invalid signature")
        return
      }

      if (response?.result === 200 && response?.response) {
        const txsData = response.response as any
        if (txsData.transactions && Array.isArray(txsData.transactions)) {
          // Convert server data to our format
          const l2psTxs: TxHistoryItem[] = txsData.transactions.map((tx: any) => ({
            hash: tx.hash, // Primary hash (Inner/Decrypted)
            outerHash: tx.encrypted_hash, // Outer hash (Encrypted)
            l1BatchHash: tx.l1_batch_hash,
            timestamp: parseInt(tx.timestamp) || Date.now(),
            type: 'l2ps' as const,
            amount: parseFloat(tx.amount) || 0,
            status: tx.status === 'confirmed' ? 'confirmed' :
              tx.status === 'batched' ? 'in_mempool' :
                tx.status === 'failed' ? 'failed' : 'pending',
            message: tx.execution_message || 'L2PS Transaction',
            from: tx.from,
            to: tx.to,
            l1_block_number: tx.l1_block_number
          }))

          setL2psHistory(l2psTxs)
          addLog(`✓ Loaded ${l2psTxs.length} L2PS transactions`)
        }
      }
    } catch (e: any) {
      console.error("Failed to fetch L2PS account transactions", e)
      addLog(`L2PS history error: ${e.message || 'Unknown'}`)
    }
  }, [l2psUid])

  // Fetch L1 Transactions
  const fetchL1Transactions = useCallback(async (demosInstance: Demos, addr: string) => {
    try {
      const cleanAddr = addr.startsWith('0x') ? addr : `0x${addr}`

      const response = await demosInstance.rpcCall({
        method: "nodeCall",
        params: [{
          message: "getTransactionHistory",
          data: {
            address: cleanAddr,
            type: "all",
            limit: 50
          },
          muid: `l1_history_${Date.now()}`
        }]
      }, false)

      if (response?.result === 200 && Array.isArray(response?.response)) {
        const txs: TxHistoryItem[] = response.response.map((tx: any) => {
          // Extract data depending on tx structure
          const content = tx.content || {};
          // For native txs, data is often [type, payload]
          let amount = content.amount || 0;

          // Try to extract amount from native payload if not at top level
          if (content.type === "native" && Array.isArray(content.data) && content.data[1]) {
            const payload = content.data[1];
            if (payload.nativeOperation === "send" && Array.isArray(payload.args)) {
              // args: [to, amount]
              amount = payload.args[1];
            }
          }

          // Ensure timestamp is a valid number
          let ts = content.timestamp;
          if (typeof ts === 'string') {
            ts = parseInt(ts, 10);
          }
          if (!ts || isNaN(ts)) {
            ts = Date.now();
          }

          return {
            hash: tx.hash,
            timestamp: ts,
            type: 'l1',
            amount: typeof amount === 'string' ? parseFloat(amount) : amount,
            status: 'confirmed', // Fetched from history usually means confirmed on L1
            from: content.from,
            to: content.to,
            l1_block_number: typeof tx.blockNumber === 'string' ? parseInt(tx.blockNumber) : tx.blockNumber
          }
        });

        setL1History(txs);
        console.log(`[L1 History] Loaded ${txs.length} transactions`);
      }
    } catch (e: any) {
      console.error("Failed to fetch L1 transactions", e)
    }
  }, [])

  // Refresh all data
  const refreshData = useCallback(async () => {
    if (!demos || !address) return

    await fetchBalance(demos, address)
    // Always fetch L1 history
    await fetchL1Transactions(demos, address)

    if (mode === 'l2ps') {
      await fetchL2PSMempoolInfo(demos)
      await fetchL2PSTransactions(demos, address)
    }
  }, [demos, address, mode, fetchBalance, fetchL2PSMempoolInfo, fetchL2PSTransactions, fetchL1Transactions])

  // Auto-refresh every 5 seconds when connected
  useEffect(() => {
    if (!isConnected || !demos) return

    const interval = setInterval(() => {
      refreshData()
    }, 5000)

    return () => clearInterval(interval)
  }, [isConnected, demos, refreshData])

  const connectWallet = async () => {
    try {
      if (!mnemonic) {
        addLog("Error: Mnemonic is required")
        return
      }

      addLog(`Connecting to node: ${nodeUrl}`)
      const demosInstance = new Demos()
      await demosInstance.connect(nodeUrl)
      addLog("Node connected")

      addLog("Connecting wallet...")
      await demosInstance.connectWallet(mnemonic)

      const addr = await demosInstance.getEd25519Address()
      const formattedAddr = addr.startsWith("0x") ? addr : `0x${addr}`

      setAddress(formattedAddr)
      setDemos(demosInstance)
      setIsConnected(true)

      // Default recipient to self
      setRecipient(formattedAddr)

      addLog(`Wallet connected: ${formattedAddr}`)

      // Initial Fetch
      await fetchBalance(demosInstance, formattedAddr)
      await fetchL1Transactions(demosInstance, formattedAddr)
      await fetchL2PSMempoolInfo(demosInstance)
      await fetchL2PSTransactions(demosInstance, formattedAddr)

    } catch (err: any) {
      addLog(`Connection Failed: ${err.message || err}`)
      console.error(err)
    }
  }

  const sendTransaction = async () => {
    if (!demos || !isConnected) return
    if (!recipient) {
      addLog("Error: Recipient address is required")
      return
    }

    // L2PS Specific Checks
    if (mode === 'l2ps') {
      if (!aesKey || !iv) {
        addLog("Error: AES Key and IV are required for L2PS encryption")
        setShowSettings(true)
        return
      }
    }

    setSending(true)
    const typeLabel = mode === 'l1' ? 'L1' : 'L2PS'
    addLog(`Preparing to send ${txCount} ${typeLabel} transactions...`)

    try {
      // Initialize L2PS if in L2PS mode
      let l2ps = null;
      if (mode === 'l2ps') {
        l2ps = await createL2PSInstance(aesKey, iv, l2psUid, nodeUrl)
      }

      const signerAddress = normalizeHex(await demos.getEd25519Address(), "Ed25519 address")
      const toAddress = normalizeHex(recipient, "Recipient address")
      const amountValue = parseFloat(amount) || 0

      let currentNonce = (await demos.getAddressNonce(signerAddress)) + 1
      addLog(`Starting nonce: ${currentNonce}`)

      for (let i = 0; i < txCount; i++) {

        const payload: TxPayload = {
          l2ps_uid: mode === 'l2ps' ? l2psUid : undefined,
          message: `${txMessage} [${i + 1}/${txCount}]`
        }

        // 1. Build Transaction 
        const tx = await buildInnerTransaction(demos, toAddress, amountValue, payload)

        let finalTx = tx;

        // 2. Encrypt (L2PS Only)
        if (mode === 'l2ps' && l2ps) {
          const encryptedTx = await l2ps.encryptTx(tx)
          const [, encryptedPayload] = encryptedTx.content.data

          // Build Outer Tx
          finalTx = await buildL2PSTransaction(
            demos,
            encryptedPayload as L2PSEncryptedPayload,
            toAddress,
            currentNonce
          )
        }

        // 3. Confirm/Verify
        const validityResponse = await demos.confirm(finalTx)

        const validityData = validityResponse.response as any
        if (!validityData?.data?.valid) {
          throw new Error(`Invalid tx: ${validityData?.data?.message ?? "Unknown"}`)
        }

        // 4. Broadcast
        await demos.broadcast(validityResponse)

        addLog(`✅ Sent ${typeLabel} Tx: ${finalTx.hash.slice(0, 12)}...`)

        addLog(`✅ Sent ${typeLabel} Tx: ${finalTx.hash.slice(0, 12)}...`)

        currentNonce++

        if (i < txCount - 1) {
          await new Promise(r => setTimeout(r, 500))
        }
      }

      addLog(`🎉 All ${txCount} transactions submitted!`)

      // Refresh data immediately after sending
      setTimeout(async () => {
        await fetchBalance(demos, address)
        await fetchL1Transactions(demos, address)
        if (mode === 'l2ps') {
          await fetchL2PSMempoolInfo(demos)
          await fetchL2PSTransactions(demos, address)
        }
      }, 1000)

    } catch (e: any) {
      addLog(`❌ Error: ${e.message || e}`)
      console.error(e)
    } finally {
      setSending(false)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'confirmed': return '#4ade80' // Green
      case 'in_mempool': return '#fbbf24' // Yellow (Batched)
      case 'pending': return '#a855f7' // Purple (Executed locally)
      case 'failed': return '#f87171' // Red
      default: return '#94a3b8'
    }
  }

  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'confirmed': return '✓ Confirmed'
      case 'in_mempool': return '📦 Batched'
      case 'pending': return '⚡ Executed'
      case 'failed': return '✗ Failed'
      default: return status
    }
  }

  return (
    <div className="App">
      <h1 className="main-title">L2PS Wallet</h1>

      {!isConnected ? (
        <div className="login-container">
          {/* Hero Banner */}
          <div className="hero-banner" style={{
            background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.2) 0%, rgba(100, 108, 255, 0.2) 100%)',
            borderRadius: '16px',
            padding: '2rem',
            marginBottom: '1.5rem',
            border: '1px solid rgba(168, 85, 247, 0.3)',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '3rem', marginBottom: '0.5rem' }}>🔐</div>
            <h2 style={{ margin: '0 0 0.5rem 0', color: '#c084fc' }}>Private Transactions Demo</h2>
            <p style={{ margin: 0, color: '#94a3b8', fontSize: '0.9rem' }}>
              Experience Layer 2 Privacy Subnets with encrypted transactions
            </p>
          </div>

          {/* Feature pills */}
          <div style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '0.5rem',
            justifyContent: 'center',
            marginBottom: '1.5rem'
          }}>
            <span style={{ padding: '0.4rem 0.8rem', background: 'rgba(168, 85, 247, 0.2)', borderRadius: '20px', fontSize: '0.75rem', color: '#c084fc' }}>
              🔒 Client-side Encryption
            </span>
            <span style={{ padding: '0.4rem 0.8rem', background: 'rgba(74, 222, 128, 0.2)', borderRadius: '20px', fontSize: '0.75rem', color: '#4ade80' }}>
              ⚡ Batch Rollups
            </span>
            <span style={{ padding: '0.4rem 0.8rem', background: 'rgba(100, 108, 255, 0.2)', borderRadius: '20px', fontSize: '0.75rem', color: '#8b93ff' }}>
              🛡️ ZK Proofs
            </span>
          </div>

          {/* Connection Card */}
          <div className="card login-card">
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span>🔌</span> Connect Wallet
            </h2>
            <div style={{ textAlign: 'left' }}>
              {/* Node URL with status indicator */}
              <label className="label" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                Node URL
                <span style={{
                  fontSize: '0.7rem',
                  padding: '0.15rem 0.4rem',
                  background: 'rgba(74, 222, 128, 0.2)',
                  borderRadius: '4px',
                  color: '#4ade80'
                }}>
                  Local
                </span>
              </label>
              <input
                value={nodeUrl}
                onChange={e => setNodeUrl(e.target.value)}
                placeholder="http://127.0.0.1:53550"
              />

              <label className="label">Mnemonic Phrase</label>
              <textarea
                rows={3}
                value={mnemonic}
                onChange={e => setMnemonic(e.target.value)}
                placeholder="Enter your 24-word recovery phrase..."
                style={{ resize: 'none' }}
              />
              <p style={{
                fontSize: '0.75rem',
                color: '#64748b',
                margin: '0.25rem 0 1rem',
                fontStyle: 'italic'
              }}>
                💡 Click "Generate New" for a fresh test wallet
              </p>

              <div className="flex-row">
                <button className="secondary-btn" onClick={generateMnemonic}>
                  🎲 Generate New
                </button>
                <button className="primary-btn" onClick={connectWallet} disabled={!mnemonic}>
                  🔗 Connect Wallet
                </button>
              </div>
            </div>
          </div>

          {/* Quick Info */}
          <div style={{
            marginTop: '1.5rem',
            padding: '1rem',
            background: 'rgba(0, 0, 0, 0.2)',
            borderRadius: '12px',
            fontSize: '0.8rem',
            color: '#64748b'
          }}>
            <strong style={{ color: '#94a3b8' }}>ℹ️ About this Demo:</strong>
            <ul style={{ margin: '0.5rem 0 0', paddingLeft: '1.25rem' }}>
              <li>Send private (L2PS) or public (L1) transactions</li>
              <li>L2PS transactions are encrypted in your browser</li>
              <li>Each L2PS transaction costs 1 DEM (burned)</li>
              <li>View the "Learn" tab for interactive explanations</li>
            </ul>
          </div>
        </div>
      ) : (
        <div className="dashboard">
          {/* Network Status Bar */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '0.5rem 1rem',
            background: 'rgba(74, 222, 128, 0.1)',
            borderRadius: '8px',
            marginBottom: '1rem',
            fontSize: '0.75rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{
                width: '8px',
                height: '8px',
                background: '#4ade80',
                borderRadius: '50%',
                boxShadow: '0 0 8px #4ade80'
              }}></span>
              <span style={{ color: '#4ade80' }}>Connected</span>
            </div>
            <div style={{ color: '#64748b' }}>
              L2PS: <span style={{ color: '#a855f7' }}>{l2psUid}</span>
            </div>
          </div>

          {/* Balance Card */}
          <div className="card balance-card">
            {/* Address with copy button */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              marginBottom: '0.5rem'
            }}>
              <p className="address-display" title={address} style={{ margin: 0 }}>
                {address.slice(0, 10)}...{address.slice(-8)}
              </p>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(address)
                  addLog('📋 Address copied!')
                }}
                style={{
                  background: 'transparent',
                  border: 'none',
                  padding: '0.25rem',
                  cursor: 'pointer',
                  opacity: 0.6
                }}
                title="Copy address"
              >
                📋
              </button>
            </div>

            {/* Balance */}
            <div className="balance-display">
              <span className="balance-value">{balance}</span>
              <span className="balance-unit">DEM</span>
            </div>

            {/* Quick stats */}
            <div style={{
              display: 'flex',
              justifyContent: 'center',
              gap: '1.5rem',
              marginTop: '1rem',
              paddingTop: '1rem',
              borderTop: '1px solid rgba(255,255,255,0.1)'
            }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#a855f7' }}>
                  {l2psHistory.length}
                </div>
                <div style={{ fontSize: '0.7rem', color: '#64748b' }}>L2PS Txs</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#646cff' }}>
                  {l1History.length}
                </div>
                <div style={{ fontSize: '0.7rem', color: '#64748b' }}>L1 Txs</div>
              </div>
              {l2psMempoolInfo && (
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#fbbf24' }}>
                    {l2psMempoolInfo.transactionCount || 0}
                  </div>
                  <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Pending</div>
                </div>
              )}
            </div>

            <button
              className="refresh-btn"
              onClick={refreshData}
              style={{
                marginTop: '1rem',
                background: 'transparent',
                border: '1px solid rgba(255,255,255,0.2)',
                padding: '0.5rem 1rem',
                fontSize: '0.8rem',
                width: '100%'
              }}
            >
              🔄 Refresh Data
            </button>
          </div>

          <div className="tabs">
            <button
              className={`tab ${activeTab === 'send' ? 'active' : ''}`}
              onClick={() => setActiveTab('send')}
            >
              Send
            </button>
            <button
              className={`tab ${activeTab === 'history' ? 'active' : ''}`}
              onClick={() => setActiveTab('history')}
            >
              History ({history.length})
            </button>
            <button
              className={`tab ${activeTab === 'learn' ? 'active' : ''}`}
              onClick={() => setActiveTab('learn')}
            >
              📚 Learn
            </button>
          </div>

          {activeTab === 'send' && (
            <div className="card send-card">
              <div className="send-form">

                {/* Mode Selector with descriptions */}
                <div style={{ marginBottom: '1.5rem' }}>
                  <div className="flex-row" style={{ marginBottom: '0.5rem' }}>
                    <button
                      className={`mode-btn ${mode === 'l2ps' ? 'active' : ''}`}
                      onClick={() => setMode('l2ps')}
                      style={{
                        background: mode === 'l2ps' ? 'linear-gradient(135deg, #a855f7, #8b5cf6)' : '#333',
                        fontWeight: mode === 'l2ps' ? 'bold' : 'normal',
                        border: mode === 'l2ps' ? '1px solid rgba(255,255,255,0.3)' : '1px solid transparent'
                      }}
                    >
                      🔒 L2PS (Private)
                    </button>
                    <button
                      className={`mode-btn ${mode === 'l1' ? 'active' : ''}`}
                      onClick={() => setMode('l1')}
                      style={{
                        background: mode === 'l1' ? 'linear-gradient(135deg, #646cff, #535bf2)' : '#333',
                        fontWeight: mode === 'l1' ? 'bold' : 'normal',
                        border: mode === 'l1' ? '1px solid rgba(255,255,255,0.3)' : '1px solid transparent'
                      }}
                    >
                      📤 L1 (Public)
                    </button>
                  </div>
                  {/* Mode description */}
                  <div style={{
                    padding: '0.5rem 0.75rem',
                    borderRadius: '6px',
                    fontSize: '0.75rem',
                    background: mode === 'l2ps' ? 'rgba(168, 85, 247, 0.1)' : 'rgba(100, 108, 255, 0.1)',
                    color: mode === 'l2ps' ? '#c084fc' : '#8b93ff'
                  }}>
                    {mode === 'l2ps'
                      ? '🔐 Encrypted in browser → Only you and recipient know the details'
                      : '📢 Public transaction → Visible to everyone on the network'
                    }
                  </div>
                </div>

                <label className="label">Recipient Address</label>
                <input
                  value={recipient}
                  onChange={e => setRecipient(e.target.value)}
                  placeholder="0x..."
                />
                <p style={{ fontSize: '0.7rem', color: '#64748b', margin: '0.25rem 0 0.5rem' }}>
                  💡 Paste any valid address or use your own for testing
                </p>

                <label className="label">Amount (DEM)</label>
                <input
                  type="number"
                  value={amount}
                  onChange={e => setAmount(e.target.value)}
                  placeholder="0.0"
                />

                <label className="label">Message</label>
                <input
                  value={txMessage}
                  onChange={e => setTxMessage(e.target.value)}
                  placeholder="Enter message..."
                />

                <label className="label">Count</label>
                <input
                  type="number"
                  min={1}
                  max={100}
                  value={txCount}
                  onChange={e => setTxCount(parseInt(e.target.value) || 1)}
                />

                {/* Fee Notice for L2PS */}
                {mode === 'l2ps' && (
                  <div className="fee-notice" style={{
                    background: 'rgba(168, 85, 247, 0.1)',
                    border: '1px solid rgba(168, 85, 247, 0.3)',
                    borderRadius: '8px',
                    padding: '0.75rem',
                    marginTop: '0.5rem',
                    fontSize: '0.85rem',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}>
                    <span style={{ color: '#94a3b8' }}>Transaction Fee (burned)</span>
                    <span style={{ fontWeight: 'bold', color: '#a855f7' }}>1 DEM</span>
                  </div>
                )}

                <button
                  className="primary-btn send-btn"
                  onClick={sendTransaction}
                  disabled={sending}
                  style={{
                    background: mode === 'l2ps' ? '#a855f7' : '#646cff'
                  }}
                >
                  {sending ? 'Sending...' : `Send ${mode === 'l2ps' ? 'Private' : 'Public'} Transaction`}
                </button>
              </div>

              {mode === 'l2ps' && (
                <div className="settings-section">
                  <button
                    className="settings-toggle"
                    onClick={() => setShowSettings(!showSettings)}
                  >
                    {showSettings ? 'Hide Advanced Settings' : 'Show Advanced Settings'}
                  </button>

                  {showSettings && (
                    <div className="settings-content">
                      <p className="info-text">
                        <strong>Why are keys here?</strong><br />
                        L2PS uses <em>Client-Side Encryption</em>. Transaction is encrypted
                        <strong> in your browser</strong> before it reaches the node.
                      </p>
                      <label className="label">Network UID</label>
                      <input value={l2psUid} onChange={e => setL2psUid(e.target.value)} />

                      <label className="label">AES Key (Hex)</label>
                      <input value={aesKey} onChange={e => setAesKey(e.target.value)} type="password" />

                      <label className="label">IV (Hex)</label>
                      <input value={iv} onChange={e => setIv(e.target.value)} type="password" />
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'history' && (
            <div className="card history-card">
              {/* History Filter Tabs */}
              <div className="history-filter-tabs" style={{
                display: 'flex',
                gap: '0.5rem',
                marginBottom: '1rem',
                padding: '0.5rem',
                background: 'rgba(0,0,0,0.2)',
                borderRadius: '8px'
              }}>
                <button
                  onClick={() => setHistoryFilter('all')}
                  style={{
                    flex: 1,
                    padding: '0.5rem',
                    border: 'none',
                    borderRadius: '6px',
                    background: historyFilter === 'all' ? 'rgba(168, 85, 247, 0.3)' : 'transparent',
                    color: historyFilter === 'all' ? '#c084fc' : '#94a3b8',
                    fontWeight: historyFilter === 'all' ? '600' : '400',
                    cursor: 'pointer',
                    transition: 'all 0.2s'
                  }}
                >
                  All ({history.length})
                </button>
                <button
                  onClick={() => setHistoryFilter('l2ps')}
                  style={{
                    flex: 1,
                    padding: '0.5rem',
                    border: 'none',
                    borderRadius: '6px',
                    background: historyFilter === 'l2ps' ? 'rgba(168, 85, 247, 0.3)' : 'transparent',
                    color: historyFilter === 'l2ps' ? '#c084fc' : '#94a3b8',
                    fontWeight: historyFilter === 'l2ps' ? '600' : '400',
                    cursor: 'pointer',
                    transition: 'all 0.2s'
                  }}
                >
                  🔒 L2PS ({l2psHistory.length})
                </button>
                <button
                  onClick={() => setHistoryFilter('l1')}
                  style={{
                    flex: 1,
                    padding: '0.5rem',
                    border: 'none',
                    borderRadius: '6px',
                    background: historyFilter === 'l1' ? 'rgba(100, 108, 255, 0.3)' : 'transparent',
                    color: historyFilter === 'l1' ? '#8b93ff' : '#94a3b8',
                    fontWeight: historyFilter === 'l1' ? '600' : '400',
                    cursor: 'pointer',
                    transition: 'all 0.2s'
                  }}
                >
                  📤 L1 ({l1History.length})
                </button>
              </div>

              {/* Filtered History */}
              {(() => {
                const filteredHistory = historyFilter === 'all'
                  ? history
                  : historyFilter === 'l2ps'
                    ? l2psHistory.sort((a, b) => b.timestamp - a.timestamp)
                    : l1History.sort((a, b) => b.timestamp - a.timestamp)

                if (filteredHistory.length === 0) {
                  return <p className="placeholder-text">No {historyFilter === 'all' ? '' : historyFilter.toUpperCase() + ' '}transactions found</p>
                }

                return (
                  <div className="history-list">
                    {filteredHistory.map((tx, i) => {
                      const isL2PS = tx.type === 'l2ps'
                      const revealed = revealedTxs.has(tx.hash)

                      const toggleRevealed = () => {
                        if (isL2PS) {
                          setRevealedTxs(prev => {
                            const next = new Set(prev)
                            if (next.has(tx.hash)) {
                              next.delete(tx.hash)
                            } else {
                              next.add(tx.hash)
                            }
                            return next
                          })
                        }
                      }

                      const copyToClipboard = (text: string, label: string) => {
                        navigator.clipboard.writeText(text)
                        addLog(`📋 Copied ${label}`)
                      }

                      return (
                        <div
                          key={tx.hash || i}
                          className={`tx-card ${isL2PS ? 'tx-l2ps' : 'tx-l1'} ${isL2PS && !revealed ? 'tx-blurred' : ''}`}
                        >
                          {/* Header Row */}
                          <div className="tx-header">
                            <div
                              className={`tx-type-badge ${isL2PS ? 'clickable' : ''}`}
                              title={isL2PS ? (revealed ? 'Click to hide details' : 'Click to reveal details') : 'L1 Public Transaction'}
                              onClick={isL2PS ? toggleRevealed : undefined}
                              style={isL2PS ? { cursor: 'pointer' } : undefined}
                            >
                              {isL2PS ? (revealed ? '🔓 L2PS' : '🔒 L2PS') : '📤 L1'}
                            </div>
                            <div
                              className="tx-status"
                              style={{ color: getStatusColor(tx.status) }}
                              title={`Status: ${tx.status}`}
                            >
                              {getStatusLabel(tx.status)}
                            </div>
                          </div>

                          {/* Transaction Details */}
                          <div className={`tx-body ${isL2PS && !revealed ? 'blurred' : ''}`}>
                            {/* Hash Row */}
                            <div className="tx-row">
                              <span className="tx-label">{isL2PS ? 'Inner Hash' : 'Hash'}</span>
                              <div className="tx-value-group">
                                <span
                                  className="tx-hash"
                                  title={`Click to copy: ${tx.hash}`}
                                  onClick={(e) => { e.stopPropagation(); copyToClipboard(tx.hash, 'hash') }}
                                >
                                  {tx.hash?.slice(0, 20)}...{tx.hash?.slice(-8)}
                                </span>
                                <button
                                  className="copy-btn"
                                  onClick={(e) => { e.stopPropagation(); copyToClipboard(tx.hash, 'hash') }}
                                  title="Copy full hash"
                                >
                                  📋
                                </button>
                              </div>
                            </div>

                            {/* Outer Hash for L2PS */}
                            {tx.outerHash && (
                              <div className="tx-row">
                                <span className="tx-label">Outer Hash</span>
                                <div className="tx-value-group">
                                  <span
                                    className="tx-hash encrypted"
                                    title={`Outer encrypted hash: ${tx.outerHash}`}
                                    onClick={(e) => { e.stopPropagation(); copyToClipboard(tx.outerHash!, 'outer hash') }}
                                  >
                                    {tx.outerHash?.slice(0, 16)}...
                                  </span>
                                  <button
                                    className="copy-btn"
                                    onClick={(e) => { e.stopPropagation(); copyToClipboard(tx.outerHash!, 'outer hash') }}
                                    title="Copy outer hash"
                                  >
                                    📋
                                  </button>
                                </div>
                              </div>
                            )}

                            {/* Amount */}
                            {tx.amount !== undefined && tx.amount > 0 && (
                              <div className="tx-row">
                                <span className="tx-label">Amount</span>
                                <span className="tx-amount">{tx.amount.toLocaleString()} DMS</span>
                              </div>
                            )}

                            {/* From/To for L2PS */}
                            {isL2PS && tx.from && (
                              <div className="tx-row">
                                <span className="tx-label">From</span>
                                <div className="tx-value-group">
                                  <span
                                    className="tx-address"
                                    onClick={(e) => { e.stopPropagation(); copyToClipboard(tx.from!, 'sender') }}
                                    title={tx.from}
                                  >
                                    {tx.from?.slice(0, 12)}...{tx.from?.slice(-6)}
                                  </span>
                                  <button
                                    className="copy-btn"
                                    onClick={(e) => { e.stopPropagation(); copyToClipboard(tx.from!, 'sender') }}
                                    title="Copy sender address"
                                  >
                                    📋
                                  </button>
                                </div>
                              </div>
                            )}

                            {isL2PS && tx.to && (
                              <div className="tx-row">
                                <span className="tx-label">To</span>
                                <div className="tx-value-group">
                                  <span
                                    className="tx-address"
                                    onClick={(e) => { e.stopPropagation(); copyToClipboard(tx.to!, 'recipient') }}
                                    title={tx.to}
                                  >
                                    {tx.to?.slice(0, 12)}...{tx.to?.slice(-6)}
                                  </span>
                                  <button
                                    className="copy-btn"
                                    onClick={(e) => { e.stopPropagation(); copyToClipboard(tx.to!, 'recipient') }}
                                    title="Copy recipient address"
                                  >
                                    📋
                                  </button>
                                </div>
                              </div>
                            )}

                            {/* Message */}
                            {tx.message && (
                              <div className="tx-row">
                                <span className="tx-label">Message</span>
                                <span className="tx-message">{tx.message}</span>
                              </div>
                            )}

                            {/* Timestamp */}
                            <div className="tx-row">
                              <span className="tx-label">Time</span>
                              <span className="tx-time" title={new Date(tx.timestamp).toISOString()}>
                                {new Date(tx.timestamp).toLocaleString()}
                              </span>
                            </div>

                            {/* L1 Block / Batch for confirmed L2PS */}
                            {(tx.l1BatchHash || tx.l1_block_number) && (
                              <div className="tx-row">
                                <span className="tx-label">L1 Context</span>
                                <div className="tx-value-column">
                                  {tx.l1_block_number && (
                                    <span className="tx-block">Block: #{tx.l1_block_number}</span>
                                  )}
                                  {tx.l1BatchHash && (
                                    <span
                                      className="tx-hash mini"
                                      title={`L1 Batch: ${tx.l1BatchHash}`}
                                      onClick={(e) => { e.stopPropagation(); copyToClipboard(tx.l1BatchHash!, 'L1 batch hash') }}
                                    >
                                      Batch: {tx.l1BatchHash?.slice(0, 12)}...
                                    </span>
                                  )}
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Privacy Notice / Toggle Button */}
                          {isL2PS && (
                            <div
                              className="tx-privacy-notice"
                              onClick={toggleRevealed}
                              style={{ cursor: 'pointer' }}
                            >
                              {revealed ? '🔒 Click to hide details' : '🔐 Click to reveal private transaction details'}
                            </div>
                          )}

                          {/* Type indicator bar */}
                          <div className={`tx-type-bar ${isL2PS ? 'bar-l2ps' : 'bar-l1'}`}></div>
                        </div>
                      )
                    })}
                  </div>
                )
              })()}
            </div>
          )}

          {/* LEARN TAB - Educational Content */}
          {activeTab === 'learn' && (
            <div className="card learn-card">
              <h2 style={{ marginBottom: '1.5rem', color: '#a855f7' }}>🎓 How L2PS Works</h2>

              {/* Section 1: What is L2PS */}
              <div className="learn-section">
                <h3>🔐 What is L2PS?</h3>
                <p>
                  <strong>Layer 2 Privacy Subnet</strong> is a private transaction layer that runs on top of the public L1 blockchain.
                </p>
                <div className="learn-box">
                  <div className="learn-comparison">
                    <div className="comparison-item l1-item">
                      <span className="comparison-title">L1 (Public)</span>
                      <span>Alice → Bob: 5 DEM</span>
                      <span className="comparison-note">Everyone sees this</span>
                    </div>
                    <div className="comparison-arrow">→</div>
                    <div className="comparison-item l2ps-item">
                      <span className="comparison-title">L2PS (Private)</span>
                      <span>Alice → [encrypted blob]</span>
                      <span className="comparison-note">Only participants know</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Section 2: Transaction Flow */}
              <div className="learn-section">
                <h3>📦 Transaction Lifecycle</h3>
                <div className="learn-timeline">
                  <div className="timeline-step">
                    <span className="step-number">1</span>
                    <div className="step-content">
                      <strong>Encrypt</strong>
                      <span>Your browser encrypts the tx with AES-256</span>
                    </div>
                  </div>
                  <div className="timeline-step">
                    <span className="step-number">2</span>
                    <div className="step-content">
                      <strong>Submit</strong>
                      <span>Encrypted blob sent to L2PS node</span>
                    </div>
                  </div>
                  <div className="timeline-step">
                    <span className="step-number">3</span>
                    <div className="step-content">
                      <strong>Execute</strong>
                      <span>Node decrypts & validates (status: ⚡ Executed)</span>
                    </div>
                  </div>
                  <div className="timeline-step">
                    <span className="step-number">4</span>
                    <div className="step-content">
                      <strong>Batch</strong>
                      <span>Per L1 block, up to 10 txs bundled (status: 📦 Batched)</span>
                    </div>
                  </div>
                  <div className="timeline-step">
                    <span className="step-number">5</span>
                    <div className="step-content">
                      <strong>Confirm</strong>
                      <span>Batch included in L1 block (status: ✓ Confirmed)</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Section 3: Fee Info */}
              <div className="learn-section">
                <h3>💰 Transaction Fees</h3>
                <div className="learn-box fee-box">
                  <div className="fee-item">
                    <span className="fee-label">L2PS Transaction Fee</span>
                    <span className="fee-value">1 DEM</span>
                  </div>
                  <p className="fee-note">
                    Each L2PS transaction costs <strong>1 DEM</strong> which is burned (removed from circulation).
                    This is in addition to the transfer amount.
                  </p>
                </div>
              </div>

              {/* Section 4: Privacy Demo - Interactive */}
              <div className="learn-section">
                <h3>🔒 Privacy Demo: Access Control</h3>
                <p>Try to fetch L2PS transaction history and see what happens with or without signing:</p>
                <div className="learn-demo">

                  {/* Initial state: Show fetch button */}
                  {!demoResult && !demoLoading && (
                    <button
                      className="demo-btn"
                      onClick={() => {
                        if (!demos) return
                        setDemoResult({ type: 'info', message: 'CHOICE_MODAL' })
                      }}
                      disabled={!demos}
                      style={{
                        background: 'linear-gradient(135deg, #a855f7, #8b5cf6)',
                      }}
                    >
                      🔍 Fetch L2PS History
                    </button>
                  )}

                  {/* Choice Modal */}
                  {demoResult?.message === 'CHOICE_MODAL' && (
                    <div style={{
                      background: 'rgba(0, 0, 0, 0.4)',
                      borderRadius: '12px',
                      padding: '1.5rem',
                      border: '1px solid rgba(168, 85, 247, 0.3)',
                      animation: 'fadeIn 0.3s ease-in'
                    }}>
                      <p style={{ marginBottom: '1rem', textAlign: 'center', fontWeight: '600' }}>
                        🔐 Authentication Required
                      </p>
                      <p style={{ marginBottom: '1.5rem', fontSize: '0.9rem', textAlign: 'center', color: '#94a3b8' }}>
                        The node requires you to prove you own the address. Sign the request?
                      </p>
                      <div style={{ display: 'flex', gap: '1rem' }}>
                        {/* Skip signing button */}
                        <button
                          className="demo-btn"
                          onClick={async () => {
                            setDemoLoading(true)
                            setDemoResult(null)
                            addLog("🧪 Attempting access WITHOUT signing...")
                            try {
                              const timestamp = Date.now().toString()
                              const response = await demos!.rpcCall({
                                method: "nodeCall",
                                params: [{
                                  message: "getL2PSAccountTransactions",
                                  data: {
                                    l2psUid: l2psUid,
                                    address: address,
                                    timestamp: timestamp,
                                    signature: "not_signed",
                                    limit: 10
                                  },
                                  muid: `demo_no_sign_${Date.now()}`
                                }]
                              }, false)

                              if (response?.result === 403) {
                                setDemoResult({ type: 'error', message: '🛡️ ACCESS DENIED (403): Cannot prove address ownership without signature!' })
                                addLog("🛡️ ACCESS DENIED (403)")
                              } else if (response?.result === 401) {
                                setDemoResult({ type: 'error', message: '🛡️ AUTH REQUIRED (401): Missing valid signature!' })
                                addLog("🛡️ AUTH REQUIRED (401)")
                              } else {
                                setDemoResult({ type: 'info', message: `Unexpected: ${response?.result}` })
                              }
                            } catch (e: any) {
                              setDemoResult({ type: 'error', message: `Error: ${e.message}` })
                            } finally {
                              setDemoLoading(false)
                            }
                          }}
                          style={{
                            flex: 1,
                            background: 'linear-gradient(135deg, #ef4444, #dc2626)',
                          }}
                        >
                          ❌ Skip Signing
                        </button>

                        {/* Sign button */}
                        <button
                          className="demo-btn"
                          onClick={async () => {
                            setDemoLoading(true)
                            setDemoResult(null)
                            addLog("✍️ Signing authentication request...")
                            try {
                              const timestamp = Date.now().toString()
                              const messageToSign = `getL2PSHistory:${address}:${timestamp}`

                              addLog(`📝 Message: ${messageToSign.slice(0, 35)}...`)

                              const signResult = await demos!.signMessage(messageToSign)
                              const signature = typeof signResult === 'string' ? signResult : signResult.data

                              addLog("✅ Signed! Sending request...")

                              const response = await demos!.rpcCall({
                                method: "nodeCall",
                                params: [{
                                  message: "getL2PSAccountTransactions",
                                  data: {
                                    l2psUid: l2psUid,
                                    address: address,
                                    timestamp: timestamp,
                                    signature: signature,
                                    limit: 10
                                  },
                                  muid: `demo_signed_${Date.now()}`
                                }]
                              }, false)

                              if (response?.result === 200) {
                                const txCount = response?.response?.transactions?.length || 0
                                setDemoResult({
                                  type: 'success',
                                  message: `✅ ACCESS GRANTED! Found ${txCount} L2PS transactions.`
                                })
                                addLog(`✅ SUCCESS! Found ${txCount} transactions`)
                              } else {
                                setDemoResult({ type: 'error', message: `Response: ${response?.result}` })
                              }
                            } catch (e: any) {
                              setDemoResult({ type: 'error', message: `Error: ${e.message}` })
                            } finally {
                              setDemoLoading(false)
                            }
                          }}
                          style={{
                            flex: 1,
                            background: 'linear-gradient(135deg, #4ade80, #22c55e)',
                          }}
                        >
                          ✍️ Sign Request
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Loading state */}
                  {demoLoading && (
                    <div style={{
                      padding: '2rem',
                      textAlign: 'center',
                      animation: 'pulse 1s infinite'
                    }}>
                      ⏳ Processing...
                    </div>
                  )}

                  {/* Result Display */}
                  {demoResult && demoResult.message !== 'CHOICE_MODAL' && !demoLoading && (
                    <div style={{ animation: 'fadeIn 0.3s ease-in' }}>
                      <div
                        style={{
                          padding: '1.25rem',
                          borderRadius: '8px',
                          background: demoResult.type === 'error'
                            ? 'rgba(239, 68, 68, 0.2)'
                            : demoResult.type === 'success'
                              ? 'rgba(74, 222, 128, 0.2)'
                              : 'rgba(100, 108, 255, 0.2)',
                          border: `1px solid ${demoResult.type === 'error'
                            ? 'rgba(239, 68, 68, 0.5)'
                            : demoResult.type === 'success'
                              ? 'rgba(74, 222, 128, 0.5)'
                              : 'rgba(100, 108, 255, 0.5)'
                            }`,
                          marginBottom: '1rem'
                        }}
                      >
                        <span style={{ fontSize: '1rem', fontWeight: '600' }}>
                          {demoResult.message}
                        </span>
                      </div>
                      <button
                        onClick={() => setDemoResult(null)}
                        style={{
                          background: 'rgba(255,255,255,0.1)',
                          border: '1px solid rgba(255,255,255,0.2)',
                          padding: '0.5rem 1rem',
                          fontSize: '0.85rem',
                          width: '100%'
                        }}
                      >
                        🔄 Try Again
                      </button>
                    </div>
                  )}

                  <p className="demo-explanation" style={{ marginTop: '1.5rem' }}>
                    <strong>How it works:</strong> L2PS history requires cryptographic proof of address ownership.
                    Without a valid signature, the node rejects the request (403).
                  </p>
                </div>
              </div>

              {/* Section 5: Encryption Demo */}
              <div className="learn-section">
                <h3>🔓 Decryption Demo</h3>
                <p>See what an encrypted L2PS transaction looks like vs decrypted:</p>
                <div className="learn-demo">
                  <div className="demo-comparison">
                    <div className="demo-box encrypted">
                      <span className="demo-label">Encrypted (What network sees)</span>
                      <code>
                        {`{
  "type": "l2psEncryptedTx",
  "to": "${l2psUid}",
  "data": "aGVsbG8gd29ybGQh..."
}`}
                      </code>
                    </div>
                    <div className="demo-arrow">🔓</div>
                    <div className="demo-box decrypted">
                      <span className="demo-label">Decrypted (Only participants see)</span>
                      <code>
                        {`{
  "type": "native",
  "from": "${address.slice(0, 16)}...",
  "to": "0xRecipient...",
  "amount": 5
}`}
                      </code>
                    </div>
                  </div>
                </div>
              </div>

              {/* Section 6: Transaction Lifecycle */}
              <div className="learn-section">
                <h3>🔄 L2PS Transaction Lifecycle</h3>
                <p>Every L2PS transaction progresses through three distinct stages of verification and finality:</p>

                <div style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '1rem',
                  marginTop: '1.5rem',
                  paddingLeft: '1rem',
                  borderLeft: '2px solid rgba(168, 85, 247, 0.3)'
                }}>
                  <div style={{ position: 'relative' }}>
                    <div style={{
                      position: 'absolute',
                      left: '-1.45rem',
                      top: '0.2rem',
                      width: '12px',
                      height: '12px',
                      borderRadius: '50%',
                      background: '#a855f7',
                      boxShadow: '0 0 10px #a855f7'
                    }}></div>
                    <strong style={{ color: '#a855f7' }}>⚡ Stage 1: Executed</strong>
                    <p style={{ margin: '0.25rem 0 0.5rem 0', fontSize: '0.85rem', color: '#94a3b8' }}>
                      Occurs within milliseconds. The local node decrypts, validates GCR edits against L1 state, and reserves the balance.
                    </p>
                  </div>

                  <div style={{ position: 'relative' }}>
                    <div style={{
                      position: 'absolute',
                      left: '-1.45rem',
                      top: '0.2rem',
                      width: '12px',
                      height: '12px',
                      borderRadius: '50%',
                      background: '#fbbf24',
                      boxShadow: '0 0 10px #fbbf24'
                    }}></div>
                    <strong style={{ color: '#fbbf24' }}>📦 Stage 2: Batched</strong>
                    <p style={{ margin: '0.25rem 0 0.5rem 0', fontSize: '0.85rem', color: '#94a3b8' }}>
                      Occurs per L1 block. Multiple private transactions are bundled into an L1 batch, and a ZK proof is generated.
                    </p>
                  </div>

                  <div style={{ position: 'relative' }}>
                    <div style={{
                      position: 'absolute',
                      left: '-1.45rem',
                      top: '0.2rem',
                      width: '12px',
                      height: '12px',
                      borderRadius: '50%',
                      background: '#4ade80',
                      boxShadow: '0 0 10px #4ade80'
                    }}></div>
                    <strong style={{ color: '#4ade80' }}>✓ Stage 3: Confirmed</strong>
                    <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.85rem', color: '#94a3b8' }}>
                      The L1 batch is included in a finalized block. Your transaction is now immutable and permanent on the blockchain.
                    </p>
                  </div>
                </div>
              </div>

              {/* Section 7: Architecture Visualization */}
              <div className="learn-section">
                <h3>🏗️ Rollup Architecture</h3>
                <div className="learn-box" style={{ padding: '1.5rem' }}>
                  <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', lineHeight: '1.6' }}>
                    <div style={{ color: '#94a3b8', marginBottom: '1rem' }}>
                      Multiple L2PS transactions are batched into a single L1 transaction:
                    </div>
                    <div style={{
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.5rem',
                      background: 'rgba(0,0,0,0.3)',
                      padding: '1rem',
                      borderRadius: '8px'
                    }}>
                      <div style={{ color: '#a855f7' }}>TX 1 ──┐</div>
                      <div style={{ color: '#a855f7' }}>TX 2 ──┤</div>
                      <div style={{ color: '#a855f7' }}>TX 3 ──┼──→ [Batch Aggregator] ──→ 1 L1 Transaction</div>
                      <div style={{ color: '#a855f7' }}>TX 4 ──┤       (per block)</div>
                      <div style={{ color: '#a855f7' }}>TX 5 ──┘</div>
                    </div>
                    <div style={{ marginTop: '1rem', color: '#94a3b8' }}>
                      <strong style={{ color: '#4ade80' }}>Benefits:</strong>
                      <ul style={{ margin: '0.5rem 0', paddingLeft: '1.5rem' }}>
                        <li>Reduced L1 congestion</li>
                        <li>Lower gas costs (amortized across batch)</li>
                        <li>Privacy preserved with ZK proofs</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>

              {/* Section 7: Key Points */}
              <div className="learn-section">
                <h3>💡 Key Takeaways</h3>
                <ul className="learn-list">
                  <li>✅ <strong>Client-side encryption</strong> - Transaction encrypted in browser with AES-256</li>
                  <li>✅ <strong>Signature verification</strong> - Only address owner can access their L2PS history</li>
                  <li>✅ <strong>Batch aggregation</strong> - Up to 10 transactions bundled per L1 block</li>
                  <li>✅ <strong>ZK Proofs</strong> - PLONK proofs verify validity without revealing content</li>
                  <li>✅ <strong>1 DEM fee</strong> - Burned per transaction (deflationary mechanism)</li>
                  <li>✅ <strong>Status tracking</strong> - Executed → Batched → Confirmed lifecycle</li>
                </ul>
              </div>

              {/* Section 8: Quick Reference */}
              <div className="learn-section" style={{ borderBottom: 'none' }}>
                <h3>📋 Quick Reference</h3>
                <div className="learn-box">
                  <table style={{
                    width: '100%',
                    fontSize: '0.85rem',
                    borderCollapse: 'collapse'
                  }}>
                    <tbody>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                        <td style={{ padding: '0.5rem 0', color: '#94a3b8' }}>L2PS UID</td>
                        <td style={{ padding: '0.5rem 0', fontFamily: 'monospace', color: '#a855f7' }}>{l2psUid}</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                        <td style={{ padding: '0.5rem 0', color: '#94a3b8' }}>Transaction Fee</td>
                        <td style={{ padding: '0.5rem 0', fontFamily: 'monospace', color: '#4ade80' }}>1 DEM (burned)</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                        <td style={{ padding: '0.5rem 0', color: '#94a3b8' }}>Batch Interval</td>
                        <td style={{ padding: '0.5rem 0', fontFamily: 'monospace' }}>Per L1 block</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                        <td style={{ padding: '0.5rem 0', color: '#94a3b8' }}>Max Batch Size</td>
                        <td style={{ padding: '0.5rem 0', fontFamily: 'monospace' }}>10 transactions</td>
                      </tr>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                        <td style={{ padding: '0.5rem 0', color: '#94a3b8' }}>Encryption</td>
                        <td style={{ padding: '0.5rem 0', fontFamily: 'monospace' }}>AES-256-CBC</td>
                      </tr>
                      <tr>
                        <td style={{ padding: '0.5rem 0', color: '#94a3b8' }}>Proof System</td>
                        <td style={{ padding: '0.5rem 0', fontFamily: 'monospace' }}>PLONK (ZK-SNARK)</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          <div className="card log-card">
            <div className="status-log">
              {logs.map((log, i) => (
                <div key={i}>{log}</div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
