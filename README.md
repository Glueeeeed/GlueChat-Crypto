# GlueChat Crypto

> High-performance cryptographic module written in Rust for [GlueChat](https://github.com/Glueeeeed/GlueChat), powered by [NAPI-RS](https://napi.rs).

## Features

- **Symmetric Encryption & Decryption**: Authenticated encryption using **XChaCha20-Poly1305** (AEAD) with 24-byte nonces and 32-byte keys.
- **ML-KEM Support**: Generate and encapsulate/decapsulate keys using ML-KEM based on NIST post-quantum standard (via `aws-lc-rs`).
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

### 2. Post-Quantum One-Time Keys (ML-KEM-1024, ML-KEM-768, ML-KEM-512)

Generate batches of One-Time Keys (OTKs) for user accounts using post-quantum key encapsulation (ML-KEM-1024, ML-KEM-768, ML-KEM-512).

```typescript
import { generateOneTimeKeys, OneTimeKey } from '@glueeeed/gluechat-crypto'

const keys = generateOneTimeKeys(KemLength.MlKem1024, 2, 'alice', 'device1');  // 2 OTKs for 'alice' on 'device1' ML-KEM-1024

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

const bytes: Uint8Array<ArrayBufferLike> = randomBytes(32);
const buffer = Buffer.from(bytes);
```

---

### 4. Encapsulation & Decapsulation (ML-KEM-1024, ML-KEM-768, ML-KEM-512)

Use ML-KEM-1024, ML-KEM-768, ML-KEM-512 post-quantum key encapsulation to establish a shared secret between two parties.

```typescript
import {
    generateOneTimeKeys,
    encapsulate,
    decapsulate,
    encrypt,
    decrypt,
    generateKemKeypair,
    KemLength
} from '@glueeeed/gluechat-crypto'


// 1. Receiver (Bob) generates a key pair
const bobsKey = generateKemKeypair(KemLength.MlKem1024);

// 2. Sender (Alice) encapsulates using Bob's public key
// Returns the KEM ciphertext (to be sent over network) and the shared secret
const {ciphertext, sharedSecret} = encapsulate(KemLength.MlKem1024,bobsKey.pubKey)

// 3. Alice encrypts a message using the shared secret
const encryptedMsg = encrypt('Hello from post-quantum world!', sharedSecret)

// --- NETWORK TRANSFER: Alice sends `ciphertext` and `encryptedMsg` to Bob ---

// 4. Bob decapsulates the ciphertext using his private key to recover the shared secret
const bobsSecret = decapsulate(KemLength.MlKem1024,bobsKey.privateKey, ciphertext)

// 5. Bob decrypts the message with the recovered secret
const decryptedMsg = decrypt(encryptedMsg, bobsSecret)
console.log(decryptedMsg) // "Hello from post-quantum world!"
```

---

### 5. Generate a Key Pair (ML-KEM-1024, ML-KEM-768, ML-KEM-512)

```typescript
import { generateKemKeypair, KemLength } from '@glueeeed/gluechat-crypto'

const keypair = generateKemKeypair(KemLength.MlKem1024) // You can use KemLength.MlKem768 or KemLength.MlKem512
```

## License

[MIT](./LICENSE)
