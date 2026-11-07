#!/usr/bin/env node
/**
 * TraceSeal Hedera sidecar.
 *
 * Single-entry CLI invoked by the Rust backend (and usable standalone for
 * setup/testing). All commands print a single JSON object to stdout.
 * Secrets come from environment variables only — never from argv.
 *
 * Commands:
 *   status                      Config + account status (no secrets echoed)
 *   setup-topic                 Create HCS topic, print { topic_id }
 *   setup-nft                   Create TSVR NFT collection, print { token_id }
 *   publish                     Submit HCS audit message
 *   mint                        Mint TSVR NFT receipt for a commitment
 *   mirror-topic                Fetch + decode HCS message by sequence number
 *   mirror-nft                  Fetch NFT info by token id + serial
 *   mirror-tx                   Fetch transaction details by transaction id
 */
import {
  AccountId,
  Client,
  Hbar,
  PrivateKey,
  TokenAssociateTransaction,
  TokenCreateTransaction,
  TokenGrantKycTransaction,
  TokenMintTransaction,
  TokenType,
  TopicCreateTransaction,
  TopicInfoQuery,
  TopicMessageQuery,
  TopicMessageSubmitTransaction,
} from "@hashgraph/sdk";

const NETWORK = (process.env.HEDERA_NETWORK || "testnet").toLowerCase();
const ACCOUNT_ID = process.env.HEDERA_ACCOUNT_ID || "";
const PRIVATE_KEY = process.env.HEDERA_PRIVATE_KEY || "";
const TOPIC_ID = process.env.HEDERA_TOPIC_ID || "";
const NFT_TOKEN_ID = process.env.HEDERA_NFT_TOKEN_ID || "";
const MIRROR_URL =
  process.env.HEDERA_MIRROR_NODE_URL ||
  `https://${NETWORK}.mirrornode.hedera.com`;

const NFT_NAME = "TraceSeal Verified Evidence";
const NFT_SYMBOL = "TSVR";
const NFT_MAX_SUPPLY = 1000;
const NFT_MEMO = "TraceSeal verified-evidence receipt";
const HCS_MEMO_PREFIX = "traceseal-audit";

function out(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}
function fail(code, message, extra = {}) {
  out({ ok: false, error: { code, message }, ...extra });
  process.exit(1);
}
function arg(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : null;
}
function hasFlag(flag) {
  return process.argv.includes(flag);
}

function requireConfig({ needTopic = false, needNft = false } = {}) {
  const missing = [];
  if (!ACCOUNT_ID) missing.push("HEDERA_ACCOUNT_ID");
  if (!PRIVATE_KEY) missing.push("HEDERA_PRIVATE_KEY");
  if (needTopic && !TOPIC_ID) missing.push("HEDERA_TOPIC_ID");
  if (needNft && !NFT_TOKEN_ID) missing.push("HEDERA_NFT_TOKEN_ID");
  if (missing.length) {
    fail(
      "HEDERA_NOT_CONFIGURED",
      `Missing environment variables: ${missing.join(", ")}. ` +
        "Set them before running Hedera operations; local verification still works without them."
    );
  }
  if (NETWORK !== "testnet" && NETWORK !== "mainnet" && NETWORK !== "previewnet") {
    fail("HEDERA_BAD_NETWORK", `Unsupported HEDERA_NETWORK '${NETWORK}'`);
  }
}

function makeClient() {
  const network =
    NETWORK === "mainnet"
      ? "mainnet"
      : NETWORK === "previewnet"
        ? "previewnet"
        : "testnet";
  const client = Client.forName(network);
  const accountId = AccountId.fromString(ACCOUNT_ID);
  const key = PrivateKey.fromString(PRIVATE_KEY);
  client.setOperator(accountId, key);
  return { client, accountId, key };
}

async function withClient(fn) {
  const { client } = makeClient();
  try {
    return await fn(client);
  } finally {
    client.close();
  }
}

function txMeta(tx, receipt) {
  return {
    transaction_id: tx.transactionId.toString(),
    transaction_valid_start: tx.transactionValidStart
      ? tx.transactionValidStart.toString()
      : null,
    consensus_timestamp: receipt.consensusTimestamp
      ? receipt.consensusTimestamp.toString()
      : null,
  };
}

/* ------------------------------ commands ------------------------------ */

async function cmdStatus() {
  const configured = Boolean(ACCOUNT_ID && PRIVATE_KEY);
  const base = {
    ok: true,
    network: NETWORK,
    mirror_node_url: MIRROR_URL,
    configured,
    account_id: ACCOUNT_ID || null,
    topic_id: TOPIC_ID || null,
    nft_token_id: NFT_TOKEN_ID || null,
    nft_name: NFT_NAME,
    nft_symbol: NFT_SYMBOL,
  };
  if (!configured) {
    out({ ...base, balance_tinybars: null, note: "HEDERA_ACCOUNT_ID/HEDERA_PRIVATE_KEY not set" });
    return;
  }
  try {
    const balance = await withClient(async (client) => {
      const b = await client.getAccountBalance(AccountId.fromString(ACCOUNT_ID));
      return b.toString();
    });
    out({ ...base, balance_tinybars: balance });
  } catch (e) {
    out({ ...base, balance_tinybars: null, account_error: String(e.message || e) });
  }
}

async function cmdSetupTopic() {
  requireConfig();
  const result = await withClient(async (client) => {
    const tx = await new TopicCreateTransaction()
      .setTopicMemo(HCS_MEMO_PREFIX)
      .setAdminKey(client.operatorPublicKey)
      .setSubmitKey(client.operatorPublicKey)
      .freezeWith(client);
    const signed = await tx.sign(client.operatorPrivateKey ?? client.operatorKey);
    const receipt = await signed.execute(client);
    const topicId = receipt.topicId.toString();
    return { ...txMeta(signed, receipt), topic_id: topicId };
  });
  out({ ok: true, ...result });
}

async function cmdSetupNft() {
  requireConfig();
  const result = await withClient(async (client) => {
    const tx = await new TokenCreateTransaction()
      .setTokenName(NFT_NAME)
      .setTokenSymbol(NFT_SYMBOL)
      .setTokenType(TokenType.NonFungibleUnique)
      .setDecimals(0)
      .setInitialSupply(0)
      .setMaxSupply(NFT_MAX_SUPPLY)
      .setTreasuryAccountId(AccountId.fromString(ACCOUNT_ID))
      .setAdminKey(client.operatorPublicKey)
      .setSupplyKey(client.operatorPublicKey)
      .setWipeKey(client.operatorPublicKey)
      .setFreezeKey(client.operatorPublicKey)
      .setKycKey(client.operatorPublicKey)
      .setMetadata([Buffer.from(NFT_MEMO)])
      .freezeWith(client);
    const signed = await tx.sign(client.operatorPrivateKey ?? client.operatorKey);
    const receipt = await signed.execute(client);
    const tokenId = receipt.tokenId.toString();
    // Grant KYC to treasury so it can receive minted NFTs.
    const kycTx = await new TokenGrantKycTransaction()
      .setTokenId(tokenId)
      .setAccountId(AccountId.fromString(ACCOUNT_ID))
      .freezeWith(client);
    const kycSigned = await kycTx.sign(client.operatorPrivateKey ?? client.operatorKey);
    const kycReceipt = await kycSigned.execute(client);
    return {
      ...txMeta(signed, receipt),
      token_id: tokenId,
      kyc_transaction_id: kycSigned.transactionId.toString(),
      kyc_consensus_timestamp: kycReceipt.consensusTimestamp
        ? kycReceipt.consensusTimestamp.toString()
        : null,
    };
  });
  out({ ok: true, ...result });
}

async function cmdPublish() {
  requireConfig({ needTopic: true });
  const message = arg("--message");
  if (!message) fail("MISSING_ARG", "--message <json-string> is required");
  let parsed;
  try {
    parsed = JSON.parse(message);
  } catch {
    fail("BAD_MESSAGE", "--message must be valid JSON");
  }
  if (parsed.schema !== "traceseal.audit.v1" || !parsed.event) {
    fail("BAD_MESSAGE", "audit message must have schema 'traceseal.audit.v1' and an event");
  }
  const result = await withClient(async (client) => {
    const tx = await new TopicMessageSubmitTransaction()
      .setTopicId(TOPIC_ID)
      .setMessage(message)
      .freezeWith(client);
    const signed = await tx.sign(client.operatorPrivateKey ?? client.operatorKey);
    const receipt = await signed.execute(client);
    const rec = receipt;
    return {
      ...txMeta(signed, rec),
      topic_id: TOPIC_ID,
      sequence_number: rec.topicSequenceNumber != null ? rec.topicSequenceNumber.toString() : null,
    };
  });
  out({ ok: true, ...result });
}

async function cmdMint() {
  requireConfig({ needNft: true });
  const metadataHex = arg("--metadata-hex");
  if (!metadataHex || !/^[0-9a-fA-F]+$/.test(metadataHex) || metadataHex.length % 2 !== 0) {
    fail("MISSING_ARG", "--metadata-hex <hex> is required (even-length hex string)");
  }
  const metadata = Buffer.from(metadataHex, "hex");
  if (metadata.length > 100) {
    fail("METADATA_TOO_LARGE", "NFT metadata exceeds 100-byte limit");
  }
  const result = await withClient(async (client) => {
    const tx = await new TokenMintTransaction()
      .setTokenId(NFT_TOKEN_ID)
      .setMetadata([metadata])
      .freezeWith(client);
    const signed = await tx.sign(client.operatorPrivateKey ?? client.operatorKey);
    const receipt = await signed.execute(client);
    const serials = receipt.serials || [];
    return {
      ...txMeta(signed, receipt),
      token_id: NFT_TOKEN_ID,
      serial_number: serials.length ? serials[0].toString() : null,
      serials: serials.map((s) => s.toString()),
    };
  });
  out({ ok: true, ...result });
}

/* --------------------------- mirror node REST -------------------------- */

async function mirrorFetch(path) {
  const url = `${MIRROR_URL}${path}`;
  const res = await fetch(url, {
    headers: { "User-Agent": "traceseal-sidecar/0.1" },
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    fail("MIRROR_HTTP_ERROR", `Mirror node returned HTTP ${res.status}`, {
      mirror_status: res.status,
      mirror_body: text.slice(0, 500),
    });
  }
  return res.json();
}

async function cmdMirrorTopic() {
  const topicId = arg("--topic-id") || TOPIC_ID;
  const sequence = arg("--sequence");
  if (!topicId || !sequence) {
    fail("MISSING_ARG", "--topic-id and --sequence are required");
  }
  const data = await mirrorFetch(
    `/api/v1/topics/${topicId}/messages?sequence.number=${sequence}&limit=1`
  );
  const msgs = data.messages || [];
  if (!msgs.length) {
    out({ ok: true, found: false, topic_id: topicId, sequence_number: sequence });
    return;
  }
  const m = msgs[0];
  let decoded = null;
  try {
    decoded = JSON.parse(Buffer.from(m.message, "base64").toString("utf8"));
  } catch {
    decoded = { raw_base64: m.message };
  }
  out({
    ok: true,
    found: true,
    topic_id: topicId,
    sequence_number: m.sequence_number != null ? String(m.sequence_number) : sequence,
    consensus_timestamp: m.consensus_timestamp || null,
    running_hash: m.running_hash || null,
    transaction_id: m.transaction_id || null,
    payer_account_id: m.payer_account_id || null,
    chunk_info: m.chunk_info || null,
    message: decoded,
  });
}

async function cmdMirrorNft() {
  const tokenId = arg("--token-id") || NFT_TOKEN_ID;
  const serial = arg("--serial");
  if (!tokenId || !serial) {
    fail("MISSING_ARG", "--token-id and --serial are required");
  }
  const data = await mirrorFetch(`/api/v1/tokens/${tokenId}/nfts?serial_number=${serial}&limit=1`);
  const nfts = data.nfts || [];
  if (!nfts.length) {
    out({ ok: true, found: false, token_id: tokenId, serial_number: serial });
    return;
  }
  const n = nfts[0];
  let metadata = null;
  if (n.metadata) {
    try {
      metadata = Buffer.from(n.metadata, "base64").toString("utf8");
    } catch {
      metadata = n.metadata;
    }
  }
  out({
    ok: true,
    found: true,
    token_id: tokenId,
    serial_number: n.serial_number != null ? String(n.serial_number) : serial,
    consensus_timestamp: n.consensus_timestamp || null,
    transaction_id: n.transaction_id || null,
    metadata,
    created_timestamp: n.created_timestamp || null,
  });
}

async function cmdMirrorTx() {
  const txId = arg("--transaction-id");
  if (!txId) fail("MISSING_ARG", "--transaction-id is required");
  const data = await mirrorFetch(`/api/v1/transactions/${txId}`);
  out({
    ok: true,
    found: true,
    transaction_id: data.transaction_id || txId,
    consensus_timestamp: data.consensus_timestamp || null,
    result: data.result || null,
    charged_tx_fee_tinybars: data.charged_tx_fee_tinybars ?? null,
    memo_base64: data.memo_base64 || null,
    valid_duration_seconds: data.valid_duration_seconds ?? null,
    node: data.node || null,
    name: data.name || null,
  });
}

/* --------------------------------- main -------------------------------- */

const commands = {
  status: cmdStatus,
  "setup-topic": cmdSetupTopic,
  "setup-nft": cmdSetupNft,
  publish: cmdPublish,
  mint: cmdMint,
  "mirror-topic": cmdMirrorTopic,
  "mirror-nft": cmdMirrorNft,
  "mirror-tx": cmdMirrorTx,
};

const cmd = process.argv[2];
if (!cmd || !commands[cmd]) {
  fail(
    "USAGE",
    "Usage: node src/cli.mjs <status|setup-topic|setup-nft|publish|mint|mirror-topic|mirror-nft|mirror-tx> [args]"
  );
}
commands[cmd]().catch((e) => {
  fail("SIDECAR_ERROR", String(e && e.message ? e.message : e));
});
