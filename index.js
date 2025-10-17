// Unsigned tx builder — Node ≥18
// Supports P2PKH (1...), P2SH (3...), and Bech32 (bc1...)
//
// Quickstart:
//   npm install
//   npm start
//
import bs58check from 'bs58check';
import { bech32, bech32m } from 'bech32';
import { Buffer } from 'buffer';

// ---- config / inputs ----
const prevTxId   = 'c30b486d2c65299a1df82d851adac158a0ec5c40aad20d9d7905c1c3aed44f49';
const vout       = 0;
const inputSat   = 20_000n;  // sats
const destAddr   = '39C7fxSzEACPjM78Z7xdPxhf7mKxJwvfMJ';
const minFeeRate = 20n;      // sat / vbyte

// ---- helpers ----
function hexLE(hex) {
  return Buffer.from(hex, 'hex').reverse(); // BE → LE
}

function varint(n) {
  if (typeof n === 'bigint') n = Number(n);
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) {
    const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b;
  }
  if (n <= 0xffffffff) {
    const b = Buffer.alloc(5); b[0] = 0xfe; b.writeUInt32LE(n, 1); return b;
  }
  const b = Buffer.alloc(9); b[0] = 0xff; b.writeBigUInt64LE(BigInt(n), 1); return b;
}

function scriptForAddress(addr) {
  // P2PKH (base58, prefix 0x00) e.g. 1...
  if (/^(1|m|n)/.test(addr)) {
    const payload = bs58check.decode(addr);
    if (payload[0] !== 0x00) throw new Error('Not a mainnet/testnet P2PKH address');
    const hash160 = payload.slice(1);
    if (hash160.length !== 20) throw new Error('P2PKH hash160 must be 20 bytes');
    return Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]), // OP_DUP OP_HASH160 PUSH(20)
      hash160,
      Buffer.from([0x88, 0xac])       // OP_EQUALVERIFY OP_CHECKSIG
    ]);
  }
  // P2SH (base58, prefix 0x05) e.g. 3...
  if (/^(3|2)/.test(addr)) {
    const payload = bs58check.decode(addr);
    if (payload[0] != 0x05) throw new Error('Not a mainnet/testnet P2SH address');
    const hash160 = payload.slice(1);
    if (hash160.length !== 20) throw new Error('P2SH hash160 must be 20 bytes');
    return Buffer.concat([
      Buffer.from([0xa9, 0x14]), // OP_HASH160 PUSH(20)
      hash160,
      Buffer.from([0x87])        // OP_EQUAL
    ]);
  }
  // Bech32/Bech32m (bc1..., tb1..., bcrt1...)
  if (/^(bc1|tb1|bcrt1)/i.test(addr)) {
    let dec;
    try { dec = bech32.decode(addr); } catch {}
    if (!dec) { dec = bech32m.decode(addr); }
    const words = dec.words;
    const version = words[0];
    const program = Buffer.from(bech32.fromWords(words.slice(1)));
    if (program.length < 2 || program.length > 40) throw new Error('Invalid witness program length');
    const verOpcode = version === 0 ? 0x00 : 0x50 + version; // OP_0..OP_16
    return Buffer.concat([
      Buffer.from([verOpcode, program.length]),
      program
    ]);
  }
  throw new Error('Unsupported address format');
}

function buildTx() {
  const scriptPubKey = scriptForAddress(destAddr);

  // Size of an *unsigned* legacy 1-in/1-out tx:
  // total = 60 + scriptPubKey.length  (vbytes == bytes here; no witness)
  const vbytes = 60n + BigInt(scriptPubKey.length);
  const fee    = minFeeRate * vbytes;
  const outSat = inputSat - fee;
  if (outSat <= 0n) throw new Error('Fee consumes the entire input.');

  const valueBuf = Buffer.alloc(8);
  valueBuf.writeBigUInt64LE(outSat);

  const tx = Buffer.concat([
    Buffer.from('02000000', 'hex'), // nVersion = 2
    varint(1),                      // #inputs
    hexLE(prevTxId),                // prev txid (LE)
    Buffer.alloc(4, 0),             // vout = 0
    varint(0),                      // empty scriptSig
    Buffer.from('ffffffff', 'hex'), // nSequence
    varint(1),                      // #outputs
    valueBuf,                       // value
    varint(scriptPubKey.length),    // script length (varint for completeness)
    scriptPubKey,                   // scriptPubKey
    Buffer.alloc(4, 0)              // locktime = 0
  ]);

  return {
    hex: tx.toString('hex'),
    info: {
      scriptPubKeyHex: scriptPubKey.toString('hex'),
      vbytes: Number(vbytes),
      fee: Number(fee),
      outputSats: Number(outSat)
    }
  };
}

const { hex, info } = buildTx();
console.log(hex);
console.error('\ninfo:', info);
