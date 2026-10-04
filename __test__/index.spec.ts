import test from 'ava'

import {
  helloCrypto,
  randomBytes,
  encrypt,
  decrypt,
  generateOneTimeKeys,
  generateKemKeypair,
  KemLength,
  encapsulate,
  decapsulate,
} from '../index'

test('helloCrypto returns expected string', (t) => {
  t.is(helloCrypto(), 'gluechat crypto wrapper works');
})

test('randomBytes generates correct byte length', (t) => {
  const bytes = randomBytes(32);
  t.is(bytes.length, 32);
})

test('encrypt and decrypt payload correctly', (t) => {
  const rawKey = randomBytes(32);
  const keyBase64 = Buffer.from(rawKey).toString('base64');

  const originalText = 'Hello GlueChat!';

  const ciphertext = encrypt(originalText, keyBase64);
  t.true(ciphertext.includes('::'));

  const decryptedText = decrypt(ciphertext, keyBase64);
  t.is(decryptedText, originalText);
})

test('generateOneTimeKeys creates requested amount of keys', (t) => {
  const keys = generateOneTimeKeys(KemLength.MlKem1024,2, 'user1', 'prefix');
  t.is(keys.length, 2);
  t.is(keys[0].accountName, 'gluechat_user1');
  t.true(keys[0].secretName.startsWith('prefix-otk-'));
  t.true(typeof keys[0].pubKey === 'string' && keys[0].pubKey.length > 0);
  t.true(typeof keys[0].privateKey === 'string' && keys[0].privateKey.length > 0);
  t.is(keys[0].pubKey.length, 2092);
  t.is(keys[0].privateKey.length, 4224);
})

test('encapsulate and decapsulate produce the same shared secret', (t) => {

  const bobsKey = generateKemKeypair(KemLength.MlKem768);

  const { ciphertext, sharedSecret } = encapsulate(KemLength.MlKem768,bobsKey.publicKey);

  t.true(typeof ciphertext === 'string' && ciphertext.length > 0);
  t.true(typeof sharedSecret === 'string' && sharedSecret.length > 0);


  const bobsSecret = decapsulate(KemLength.MlKem768,bobsKey.privateKey, ciphertext);

  t.is(sharedSecret, bobsSecret);
})

test('decapsulate with wrong private key produces different shared secret', (t) => {
  const bobsKey = generateKemKeypair(KemLength.MlKem512);
  const evesKey = generateKemKeypair(KemLength.MlKem512);

  const { sharedSecret, ciphertext } = encapsulate(KemLength.MlKem512, bobsKey.publicKey);

  const evesSecret = decapsulate(KemLength.MlKem512, evesKey.privateKey, ciphertext);

  t.not(sharedSecret, evesSecret);
})

test('encrypt and decrypt using ML-KEM shared secret', (t) => {
  const receiverKey = generateKemKeypair(KemLength.MlKem512);

  const { ciphertext, sharedSecret } = encapsulate(KemLength.MlKem512,receiverKey.publicKey);
  const message = 'Post-Quantum GlueChat Message';
  const encryptedPayload = encrypt(message, sharedSecret);

  const recoveredSecret = decapsulate(KemLength.MlKem512,receiverKey.privateKey, ciphertext);
  const decryptedMessage = decrypt(encryptedPayload, recoveredSecret);

  t.is(decryptedMessage, message);
})

test('generate ML-KEM pair of keys', (t) => {
  const aliceKey = generateKemKeypair(KemLength.MlKem1024);


  t.truthy(aliceKey.privateKey);
  t.truthy(aliceKey.publicKey);

  t.is(aliceKey.publicKey.length, 2092);
  t.is(aliceKey.privateKey.length, 4224);
});