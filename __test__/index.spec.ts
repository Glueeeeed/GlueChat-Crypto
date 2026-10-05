import test from 'ava'

import {
  helloCrypto,
  randomBytes,
  encrypt,
  decrypt,
  generateOneTimeKeys,
  mlDsaKeypair,
  mlDsaSign,
  mlDsaVerify,
  kemKeypair,
  MlDsaLength,
  KemLength,
  encapsulate,
  decapsulate,
} from '../index'

test('helloCrypto returns expected string', (t) => {
  t.is(helloCrypto(), 'gluechat crypto wrapper works')
})

test('randomBytes generates correct byte length', (t) => {
  const bytes = randomBytes(32)
  t.is(bytes.length, 32)
  t.true(bytes instanceof Uint8Array)
})

test('encrypt and decrypt payload correctly', (t) => {
  const key = randomBytes(32)
  const originalText = 'Hello GlueChat!'
  const plaintext = Buffer.from(originalText)

  const ciphertext = encrypt(plaintext, key)
  t.true(ciphertext instanceof Uint8Array)

  const decryptedBytes = decrypt(ciphertext, key)
  t.true(decryptedBytes instanceof Uint8Array)
  t.is(Buffer.from(decryptedBytes).toString('utf-8'), originalText)
})

test('generateOneTimeKeys creates requested amount of keys', (t) => {
  const keys = generateOneTimeKeys(KemLength.MlKem1024, 2, 'user1', 'prefix')
  t.is(keys.length, 2)
  t.is(keys[0].accountName, 'gluechat_user1')
  t.true(keys[0].secretName.startsWith('prefix-otk-'))
  t.true(keys[0].pubKey instanceof Uint8Array && keys[0].pubKey.length > 0)
  t.true(keys[0].privateKey instanceof Uint8Array && keys[0].privateKey.length > 0)
  t.is(keys[0].pubKey.length, 1568)
  t.is(keys[0].privateKey.length, 3168)
})

test('encapsulate and decapsulate produce the same shared secret', (t) => {
  const bobsKey = kemKeypair(KemLength.MlKem768)

  const { ciphertext, sharedSecret } = encapsulate(KemLength.MlKem768, bobsKey.publicKey)

  t.true(ciphertext instanceof Uint8Array && ciphertext.length > 0)
  t.true(sharedSecret instanceof Uint8Array && sharedSecret.length > 0)

  const bobsSecret = decapsulate(KemLength.MlKem768, bobsKey.privateKey, ciphertext)

  t.deepEqual(sharedSecret, bobsSecret)
})

test('decapsulate with wrong private key produces different shared secret', (t) => {
  const bobsKey = kemKeypair(KemLength.MlKem512)
  const evvesKey = kemKeypair(KemLength.MlKem512)

  const { sharedSecret, ciphertext } = encapsulate(KemLength.MlKem512, bobsKey.publicKey)

  const evesSecret = decapsulate(KemLength.MlKem512, evvesKey.privateKey, ciphertext)

  t.notDeepEqual(sharedSecret, evesSecret)
})

test('encrypt and decrypt using ML-KEM shared secret', (t) => {
  const receiverKey = kemKeypair(KemLength.MlKem512)

  const { ciphertext, sharedSecret } = encapsulate(KemLength.MlKem512, receiverKey.publicKey)
  const message = 'Post-Quantum GlueChat Message'
  const messageBytes = Buffer.from(message)
  const encryptedPayload = encrypt(messageBytes, sharedSecret)

  const recoveredSecret = decapsulate(KemLength.MlKem512, receiverKey.privateKey, ciphertext)
  const decryptedBytes = decrypt(encryptedPayload, recoveredSecret)

  t.is(Buffer.from(decryptedBytes).toString('utf-8'), message)
})

test('generate ML-KEM pair of keys', (t) => {
  const aliceKey = kemKeypair(KemLength.MlKem1024)

  t.truthy(aliceKey.privateKey)
  t.truthy(aliceKey.publicKey)
  t.true(aliceKey.publicKey instanceof Uint8Array)
  t.true(aliceKey.privateKey instanceof Uint8Array)

  t.is(aliceKey.publicKey.length, 1568)
  t.is(aliceKey.privateKey.length, 3168)
})

test('generate ML-DSA pair of keys', (t) => {
  const aliceKey = mlDsaKeypair(MlDsaLength.MlDsa65)
  t.truthy(aliceKey.privateKey)
  t.truthy(aliceKey.publicKey)
  t.true(aliceKey.publicKey instanceof Uint8Array)
  t.true(aliceKey.privateKey instanceof Uint8Array)

  t.is(aliceKey.publicKey.length, 1952)
  t.is(aliceKey.privateKey.length, 4032)
})

test('sign and verify using ML-DSA', (t) => {
  const aliceKey = mlDsaKeypair(MlDsaLength.MlDsa44)
  const message = Buffer.from('Important Message to Sign')

  const signature = mlDsaSign(MlDsaLength.MlDsa44, aliceKey.privateKey, message)
  t.truthy(signature)
  t.true(signature instanceof Uint8Array && signature.length > 0)

  const isValid = mlDsaVerify(MlDsaLength.MlDsa44, aliceKey.publicKey, message, signature)
  t.true(isValid)

  const isInvalid = mlDsaVerify(MlDsaLength.MlDsa44, aliceKey.publicKey, Buffer.from('Tampered Message'), signature)
  t.false(isInvalid)
})