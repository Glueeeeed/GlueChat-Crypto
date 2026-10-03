import test from 'ava'

import {
  helloCrypto,
  randomBytes,
  encrypt,
  decrypt,
  generateOneTimeKeys,
} from '../index'

test('helloCrypto returns expected string', (t) => {
  t.is(helloCrypto(), 'crypto wrapper works')
})

test('randomBytes generates correct byte length', (t) => {
  const bytes = randomBytes(32)
  t.is(bytes.length, 32)
})

test('encrypt and decrypt payload correctly', (t) => {
  const rawKey = randomBytes(32)
  const keyBase64 = Buffer.from(rawKey).toString('base64')

  const originalText = 'Hello GlueChat!'

  const ciphertext = encrypt(originalText, keyBase64)
  t.true(ciphertext.includes('::'))

  const decryptedText = decrypt(ciphertext, keyBase64)
  t.is(decryptedText, originalText)
})

test('generateOneTimeKeys creates requested amount of keys', (t) => {
  const keys = generateOneTimeKeys(2, 'user1', 'prefix')
  t.is(keys.length, 2)
  t.is(keys[0].accountName, 'gluechat_user1')
  t.true(keys[0].secretName.startsWith('prefix-otk-'))
})