# `@glueeeed/gluechat-crypto`

> High-performance cryptographic module written in Rust for [GlueChat](https://github.com/Glueeeeed/GlueChat), powered by [NAPI-RS](https://napi.rs).

## Features

- **Symmetric Encryption & Decryption**: Authenticated encryption using **XChaCha20-Poly1305** (AEAD) with 24-byte nonces and 32-byte keys.
- **Post-Quantum Key Exchange (ML-KEM-1024)**: One-Time Key (OTK) pair generation based on NIST post-quantum standard ML-KEM-1024 (via `aws-lc-rs`).
- **Native Performance**: Implemented in Rust with zero-overhead Node-API (`napi-rs`) bindings.

---

## Installation

```bash
# Using npm
npm install @glueeeed/gluechat-crypto

# Using yarn
yarn add @glueeeed/gluechat-crypto

# Using pnpm
pnpm add @glueeeed/gluechat-crypto
```

---

## API & Usage

### 1. Symmetric Encryption & Decryption (XChaCha20-Poly1305)

Encrypt and decrypt messages using a 32-byte base64-encoded key. Ciphertext output follows the `ciphertext_base64::nonce_base64` format.

```typescript
import { encrypt, decrypt, randomBytes } from '@glueeeed/gluechat-crypto'

// 1. Generate a random 32-byte key (Base64)
const rawKey = randomBytes(32)
const keyBase64 = Buffer.from(rawKey).toString('base64')

const message = 'Hello GlueChat!'

// 2. Encrypt plaintext
const ciphertext = encrypt(message, keyBase64)
console.log('Encrypted payload:', ciphertext) // "<base64_payload>::<base64_nonce>"

// 3. Decrypt ciphertext
const decrypted = decrypt(ciphertext, keyBase64)
console.log('Decrypted message:', decrypted) // "Hello GlueChat!"
```

---

### 2. Post-Quantum One-Time Keys (ML-KEM-1024)

Generate batches of One-Time Keys (OTKs) for user accounts using post-quantum key encapsulation (ML-KEM-1024).

```typescript
import { generateOneTimeKeys, OneTimeKey } from '@glueeeed/gluechat-crypto'

const keys: OneTimeKey[] = generateOneTimeKeys(5, 'alice', 'device1')

console.log(keys)
/*
[
  {
    accountName: 'gluechat_alice',
    secretName: 'device1-otk-a1b2c3d4',
    id: 'a1b2c3d4',
    pubKey: '<base64_public_key>',
    privateKey: '<base64_private_key>'
  },
  ...
]
*/
```

---

### 3. Random Bytes

Generate cryptographically secure random bytes.

```typescript
import { randomBytes } from '@glueeeed/gluechat-crypto'

const bytes: number[] = randomBytes(32)
const buffer = Buffer.from(bytes)
```

---

## License

[MIT](./LICENSE)
