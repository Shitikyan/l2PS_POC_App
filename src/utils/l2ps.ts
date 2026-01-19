
import { Demos } from "@kynesyslabs/demosdk/websdk"
import { L2PS } from "@kynesyslabs/demosdk/l2ps"
import type { L2PSEncryptedPayload } from "@kynesyslabs/demosdk/l2ps"
import type { Transaction } from "@kynesyslabs/demosdk/types"
import forge from "node-forge"

export type { L2PSEncryptedPayload }

export interface TxPayload {
    message?: string
    l2ps_uid?: string
    [key: string]: unknown
}

export function normalizeHex(address: string, label: string = "Address"): string {
    if (!address) {
        throw new Error(`${label} is required`)
    }

    const cleaned = address.trim()
    const hex = cleaned.startsWith("0x") ? cleaned : `0x${cleaned}`

    if (hex.length !== 66) {
        throw new Error(`${label} invalid: Expected 64 hex characters (32 bytes) with 0x prefix, but got ${hex.length - 2} characters.`)
    }

    if (!/^0x[0-9a-fA-F]{64}$/.test(hex)) {
        throw new Error(`${label} contains invalid hex characters.`)
    }

    return hex.toLowerCase()
}

export function sanitizeHexValue(value: string, label: string): string {
    if (!value || typeof value !== "string") {
        throw new Error(`Missing ${label}`)
    }

    const cleaned = value.trim().replace(/^0x/, "").replaceAll(/\s+/g, "")

    if (cleaned.length === 0) {
        throw new Error(`${label} is empty`)
    }

    if (cleaned.length % 2 !== 0) {
        throw new Error(`${label} has invalid length (must be even number of hex chars)`)
    }

    if (!/^[0-9a-fA-F]+$/.test(cleaned)) {
        throw new Error(`${label} contains non-hex characters`)
    }

    return cleaned.toLowerCase()
}

export async function buildInnerTransaction(
    demos: Demos,
    to: string,
    amount: number,
    payload: TxPayload,
    operation = "send",
): Promise<Transaction> {
    const tx = await demos.tx.prepare()
    tx.content.type = "native" as Transaction["content"]["type"]
    tx.content.to = normalizeHex(to)
    tx.content.amount = amount
    // Format as native payload with send operation for L2PSTransactionExecutor
    tx.content.data = ["native", {
        nativeOperation: operation,
        args: [normalizeHex(to), amount],
        ...payload  // Include l2ps_uid and other metadata
    }] as unknown as Transaction["content"]["data"]
    tx.content.timestamp = Date.now()

    return demos.sign(tx)
}

export async function buildL2PSTransaction(
    demos: Demos,
    payload: L2PSEncryptedPayload,
    to: string,
    nonce: number,
): Promise<Transaction> {
    const tx = await demos.tx.prepare()
    tx.content.type = "l2psEncryptedTx" as Transaction["content"]["type"]
    tx.content.to = normalizeHex(to)
    tx.content.amount = 0
    tx.content.data = ["l2psEncryptedTx", payload] as unknown as Transaction["content"]["data"]
    tx.content.nonce = nonce
    tx.content.timestamp = Date.now()

    return demos.sign(tx)
}

export async function createL2PSInstance(keyHex: string, ivHex: string, uid: string, nodeUrl: string): Promise<L2PS> {
    const hexKey = sanitizeHexValue(keyHex, "L2PS key")
    const hexIv = sanitizeHexValue(ivHex, "L2PS IV")
    const keyBytes = forge.util.hexToBytes(hexKey)
    const ivBytes = forge.util.hexToBytes(hexIv)

    const l2ps = await L2PS.create(keyBytes, ivBytes)
    l2ps.setConfig({ uid: uid, config: { created_at_block: 0, known_rpcs: [nodeUrl] } })
    return l2ps
}
