# GlueChat Crypto

> High-performance cryptographic module written in Rust for [GlueChat](https://github.com/Glueeeeed/GlueChat), powered by [NAPI-RS](https://napi.rs).

## Features

- **Symmetric Encryption & Decryption**: Authenticated encryption using **XChaCha20-Poly1305** (AEAD) with 24-byte nonces and 32-byte keys.
- **ML-KEM Support**: Generate and encapsulate/decapsulate keys using ML-KEM based on NIST post-quantum standard (via `aws-lc-rs`).
- **ML-DSA Support**: Generate, sign, and verify digital signatures using ML-DSA based on NIST post-quantum standard (via `aws-lc-rs`).
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

Encrypt and decrypt messages using a 32-byte key (`Uint8Array`). Ciphertext output contains the 24-byte nonce followed by the encrypted payload.

```typescript
import { encrypt, decrypt, randomBytes } from '@glueeeed/gluechat-crypto'

// 1. Generate a random 32-byte key
const key = randomBytes(32)

const message = Buffer.from('Hello GlueChat!')

// 2. Encrypt plaintext
const ciphertext = encrypt(message, key)
console.log('Encrypted payload:', ciphertext) // Uint8Array [nonce (24 bytes) + ciphertext]

// 3. Decrypt ciphertext
const decrypted = decrypt(ciphertext, key)
console.log('Decrypted message:', Buffer.from(decrypted).toString('utf-8')) // "Hello GlueChat!"
```

---

### 2. Post-Quantum One-Time Keys (ML-KEM-1024, ML-KEM-768, ML-KEM-512)

Generate batches of One-Time Keys (OTKs) for user accounts using post-quantum key encapsulation (ML-KEM-1024, ML-KEM-768, ML-KEM-512).

```typescript
import { generateOneTimeKeys, KemLength } from '@glueeeed/gluechat-crypto'

const keys = generateOneTimeKeys(KemLength.MlKem1024, 2, 'alice', 'device1');  // 2 OTKs for 'alice' on 'device1' ML-KEM-1024

console.log(keys)
/*
[
  {
    accountName: 'gluechat_alice',
    secretName: 'device1-otk-a1b2c3d4',
    id: 'a1b2c3d4',
    pubKey: Uint8Array(...),
    privateKey: Uint8Array(...)
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

const bytes: Uint8Array = randomBytes(32);
const buffer = Buffer.from(bytes);
```

---

### 4. Encapsulation & Decapsulation (ML-KEM-1024, ML-KEM-768, ML-KEM-512)

Use ML-KEM-1024, ML-KEM-768, ML-KEM-512 post-quantum key encapsulation to establish a shared secret between two parties.

```typescript
import {
    encapsulate,
    decapsulate,
    encrypt,
    decrypt,
    kemKeypair,
    KemLength
} from '@glueeeed/gluechat-crypto'


// 1. Receiver (Bob) generates a key pair
const bobsKey = kemKeypair(KemLength.MlKem1024);

// 2. Sender (Alice) encapsulates using Bob's public key
// Returns the KEM ciphertext (to be sent over network) and the shared secret
const {ciphertext, sharedSecret} = encapsulate(KemLength.MlKem1024, bobsKey.publicKey)

// 3. Alice encrypts a message using the shared secret
const encryptedMsg = encrypt(Buffer.from('Hello from post-quantum world!'), sharedSecret)

// --- NETWORK TRANSFER: Alice sends `ciphertext` and `encryptedMsg` to Bob ---

// 4. Bob decapsulates the ciphertext using his private key to recover the shared secret
const bobsSecret = decapsulate(KemLength.MlKem1024, bobsKey.privateKey, ciphertext)

// 5. Bob decrypts the message with the recovered secret
const decryptedMsg = decrypt(encryptedMsg, bobsSecret)
console.log(Buffer.from(decryptedMsg).toString('utf-8')) // "Hello from post-quantum world!"
```

---

### 5. Generate a Key Pair (ML-KEM-1024, ML-KEM-768, ML-KEM-512)

```typescript
import { kemKeypair, KemLength } from '@glueeeed/gluechat-crypto'

const keypair = kemKeypair(KemLength.MlKem1024) // You can use KemLength.MlKem768 or KemLength.MlKem512
```

---

### 6. Digital Signatures (ML-DSA-44, ML-DSA-65, ML-DSA-87)

Generate post-quantum digital signatures using ML-DSA.

```typescript
import { mlDsaKeypair, mlDsaSign, mlDsaVerify, MlDsaLength } from '@glueeeed/gluechat-crypto'

// 1. Generate a signing key pair
const keypair = mlDsaKeypair(MlDsaLength.MlDsa44)

const message = Buffer.from('Message to sign')

// 2. Sign a message
const signature = mlDsaSign(MlDsaLength.MlDsa44, keypair.privateKey, message)

// 3. Verify the signature
const isValid = mlDsaVerify(MlDsaLength.MlDsa44, keypair.publicKey, message, signature)
console.log('Signature valid:', isValid) // true
```

## License

[MIT](./LICENSE)
