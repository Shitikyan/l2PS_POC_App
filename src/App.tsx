
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
  const [activeTab, setActiveTab] = useState<'send' | 'history'>('send')

  // Combine history whenever L1 or L2PS history changes
  useEffect(() => {
    setHistory([...l1History, ...l2psHistory].sort((a, b) => b.timestamp - a.timestamp))
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

  // Check individual transaction status
  const checkTxStatus = useCallback(async (demosInstance: Demos, txHash: string): Promise<string> => {
    try {
      const status = await demosInstance.getTxByHash(txHash)
      if (status) {
        return 'confirmed'
      }
      return 'pending'
    } catch {
      return 'pending'
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
        <div className="card login-card">
          <h2>Connect Wallet</h2>
          <div style={{ textAlign: 'left' }}>
            <label className="label">Node URL</label>
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
              placeholder="Enter 24-word mnemonic"
            />

            <div className="flex-row">
              <button className="secondary-btn" onClick={generateMnemonic}>Generate New</button>
              <button className="primary-btn" onClick={connectWallet} disabled={!mnemonic}>Connect Wallet</button>
            </div>
          </div>
        </div>
      ) : (
        <div className="dashboard">
          <div className="card balance-card">
            <p className="address-display" title={address}>{address.slice(0, 10)}...{address.slice(-8)}</p>
            <div className="balance-display">
              <span className="balance-value">{balance}</span>
              <span className="balance-unit">DMS</span>
            </div>
            <button
              className="refresh-btn"
              onClick={refreshData}
              style={{ marginTop: '1rem', background: 'transparent', border: '1px solid rgba(255,255,255,0.2)', padding: '0.5rem 1rem', fontSize: '0.8rem' }}
            >
              🔄 Refresh
            </button>

            {/* L2PS Mempool Status */}
            {l2psMempoolInfo && mode === 'l2ps' && (
              <div style={{ marginTop: '1rem', fontSize: '0.8rem', opacity: 0.7 }}>
                <span>L2PS Mempool: {l2psMempoolInfo.transactionCount || 0} txs</span>
              </div>
            )}
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
          </div>

          {activeTab === 'send' && (
            <div className="card send-card">
              <div className="send-form">

                <div className="flex-row" style={{ marginBottom: '1rem' }}>
                  <button
                    className={`mode-btn ${mode === 'l2ps' ? 'active' : ''}`}
                    onClick={() => setMode('l2ps')}
                    style={{
                      background: mode === 'l2ps' ? '#a855f7' : '#333',
                      fontWeight: mode === 'l2ps' ? 'bold' : 'normal',
                      border: mode === 'l2ps' ? '1px solid white' : '1px solid transparent'
                    }}
                  >
                    L2PS (Private)
                  </button>
                  <button
                    className={`mode-btn ${mode === 'l1' ? 'active' : ''}`}
                    onClick={() => setMode('l1')}
                    style={{
                      background: mode === 'l1' ? '#646cff' : '#333',
                      fontWeight: mode === 'l1' ? 'bold' : 'normal',
                      border: mode === 'l1' ? '1px solid white' : '1px solid transparent'
                    }}
                  >
                    L1 (Public)
                  </button>
                </div>

                <label className="label">Recipient Address</label>
                <input
                  value={recipient}
                  onChange={e => setRecipient(e.target.value)}
                  placeholder="0x..."
                />

                <label className="label">Amount (DMS)</label>
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
              {history.length === 0 ? (
                <p className="placeholder-text">No transactions found</p>
              ) : (
                <div className="history-list">
                  {history.map((tx, i) => {
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
              )}
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
