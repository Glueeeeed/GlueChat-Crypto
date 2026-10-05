use aws_lc_rs::encoding::AsRawBytes;
use aws_lc_rs::kem::{
  Algorithm, Ciphertext, DecapsulationKey, DecapsulationKeyBytes, EncapsulationKey,
  EncapsulationKeyBytes, ML_KEM_1024, ML_KEM_512, ML_KEM_768,
};
use aws_lc_rs::signature::{
  KeyPair, PqdsaKeyPair, PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm, UnparsedPublicKey,
};
use aws_lc_rs::{rand, signature};
use chacha20poly1305::{
  aead::{Aead, KeyInit},
  XChaCha20Poly1305, XNonce,
};
use napi::bindgen_prelude::Uint8Array;
use napi::Error;
use napi_derive::napi;

use hex::encode as hex_encode;

#[napi(object)]
pub struct KEMKeyPair {
  pub private_key: Uint8Array,
  pub public_key: Uint8Array,
}

#[napi(object)]
pub struct OneTimeKey {
  pub account_name: String,
  pub secret_name: String,
  pub id: String,
  pub pub_key: Uint8Array,
  pub private_key: Uint8Array,
}

#[napi(object)]
pub struct EncapsulationResult {
  pub ciphertext: Uint8Array,
  pub shared_secret: Uint8Array,
}

#[napi]
pub enum KemLength {
  MlKem1024,
  MlKem768,
  MlKem512,
}

#[napi]
pub enum MlDsaLength {
  MlDsa87,
  MlDsa65,
  MlDsa44,
}

#[napi(object)]
pub struct DSAKeyPair {
  pub private_key: Uint8Array,
  pub public_key: Uint8Array,
}

#[napi]
pub fn ml_dsa_keypair(length: MlDsaLength) -> napi::Result<DSAKeyPair> {
  let algorithm: &'static PqdsaSigningAlgorithm = match length {
    MlDsaLength::MlDsa44 => &signature::ML_DSA_44_SIGNING,
    MlDsaLength::MlDsa65 => &signature::ML_DSA_65_SIGNING,
    MlDsaLength::MlDsa87 => &signature::ML_DSA_87_SIGNING,
  };

  let key_pair = PqdsaKeyPair::generate(algorithm)
    .map_err(|_| Error::from_reason("Failed to generate key pair"))?;

  let public_key_bytes = key_pair.public_key().as_ref();

  let private_key_bytes = key_pair
    .private_key()
    .as_raw_bytes()
    .map_err(|_| Error::from_reason("Failed to generate key pair"))?;

  let private_key = Uint8Array::from(private_key_bytes.as_ref());
  let public_key = Uint8Array::from(public_key_bytes);

  Ok(DSAKeyPair {
    private_key,
    public_key,
  })
}

#[napi]
pub fn ml_dsa_sign(
  length: MlDsaLength,
  private_key: Uint8Array,
  message: Uint8Array,
) -> napi::Result<Uint8Array> {
  let algorithm: &'static PqdsaSigningAlgorithm = match length {
    MlDsaLength::MlDsa44 => &signature::ML_DSA_44_SIGNING,
    MlDsaLength::MlDsa65 => &signature::ML_DSA_65_SIGNING,
    MlDsaLength::MlDsa87 => &signature::ML_DSA_87_SIGNING,
  };

  let priv_key_bytes = private_key.as_ref();

  let key_pair = PqdsaKeyPair::from_raw_private_key(algorithm, priv_key_bytes)
    .map_err(|_| Error::from_reason("Invalid private key bytes"))?;

  let mut signature = vec![0u8; algorithm.signature_len()];
  key_pair
    .sign(message.as_ref(), &mut signature)
    .map_err(|_| Error::from_reason("Signing failed"))?;

  Ok(Uint8Array::from(signature))
}

#[napi]
pub fn ml_dsa_verify(
  length: MlDsaLength,
  public_key: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
) -> napi::Result<bool> {
  let algorithm: &'static PqdsaVerificationAlgorithm = match length {
    MlDsaLength::MlDsa44 => &signature::ML_DSA_44,
    MlDsaLength::MlDsa65 => &signature::ML_DSA_65,
    MlDsaLength::MlDsa87 => &signature::ML_DSA_87,
  };

  let pub_key_bytes = public_key.as_ref();
  let signature_bytes = signature.as_ref();

  let public_key = UnparsedPublicKey::new(algorithm, pub_key_bytes);

  match public_key.verify(message.as_ref(), signature_bytes) {
    Ok(_) => Ok(true),
    Err(_) => Ok(false),
  }
}

#[napi]
pub fn encapsulate(length: KemLength, public_key: Uint8Array) -> napi::Result<EncapsulationResult> {
  let algorithm: &'static Algorithm = match length {
    KemLength::MlKem1024 => &ML_KEM_1024,
    KemLength::MlKem768 => &ML_KEM_768,
    KemLength::MlKem512 => &ML_KEM_512,
  };

  let pub_key_bytes = public_key.as_ref();

  let enc_key = EncapsulationKey::new(algorithm, pub_key_bytes)
    .map_err(|_| Error::from_reason("Invalid public key bytes"))?;

  let (ciphertext_bytes, shared_secret) = enc_key
    .encapsulate()
    .map_err(|_| Error::from_reason("Encapsulation failed"))?;

  Ok(EncapsulationResult {
    ciphertext: Uint8Array::from(ciphertext_bytes.as_ref()),
    shared_secret: Uint8Array::from(shared_secret.as_ref()),
  })
}

#[napi]
pub fn decapsulate(
  length: KemLength,
  private_key: Uint8Array,
  ciphertext: Uint8Array,
) -> napi::Result<Uint8Array> {
  let algorithm: &'static Algorithm = match length {
    KemLength::MlKem1024 => &ML_KEM_1024,
    KemLength::MlKem768 => &ML_KEM_768,
    KemLength::MlKem512 => &ML_KEM_512,
  };

  let priv_key_bytes = private_key.as_ref();
  let ciphertext_bytes = ciphertext.as_ref();

  let dec_key = DecapsulationKey::new(algorithm, priv_key_bytes)
    .map_err(|_| Error::from_reason("Invalid private key bytes"))?;

  let ciphertext = Ciphertext::from(ciphertext_bytes);

  let shared_secret = dec_key
    .decapsulate(ciphertext)
    .map_err(|_| Error::from_reason("Decapsulation failed"))?;

  Ok(Uint8Array::from(shared_secret.as_ref()))
}

#[napi]
pub fn hello_crypto() -> String {
  "gluechat crypto wrapper works".to_string()
}

#[napi]
pub fn random_bytes(length: u32) -> Uint8Array {
  let mut bytes = vec![0u8; length as usize];
  let _ = rand::fill(&mut bytes[..]);
  Uint8Array::from(bytes)
}

#[napi]
pub fn encrypt(plaintext: Uint8Array, key: Uint8Array) -> napi::Result<Uint8Array> {
  let key_bytes = key.as_ref();
  if key_bytes.len() != 32 {
    return Err(Error::from_reason("Key must be 32 bytes long"));
  }

  let cipher =
    XChaCha20Poly1305::new_from_slice(key_bytes).map_err(|_| Error::from_reason("Invalid key"))?;

  let mut nonce_bytes: [u8; 24] = [0u8; 24];
  rand::fill(&mut nonce_bytes).map_err(|_| Error::from_reason("Random generation failed"))?;
  let nonce = XNonce::try_from(nonce_bytes.as_slice())
    .map_err(|_| Error::from_reason("Invalid nonce length"))?;

  let ciphertext: Vec<u8> = cipher
    .encrypt(&nonce, plaintext.as_ref())
    .map_err(|_| Error::from_reason("Encryption failed"))?;

  let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
  combined.extend_from_slice(&nonce_bytes);
  combined.extend_from_slice(&ciphertext);

  Ok(Uint8Array::from(combined))
}

#[napi]
pub fn decrypt(ciphertext: Uint8Array, key: Uint8Array) -> napi::Result<Uint8Array> {
  let ciphertext_bytes = ciphertext.as_ref();
  if ciphertext_bytes.len() < 24 {
    return Err(Error::from_reason(
      "Invalid ciphertext length. Must be at least 24 bytes (nonce)",
    ));
  }

  let (nonce_bytes, payload_bytes) = ciphertext_bytes.split_at(24);

  let key_bytes = key.as_ref();
  if key_bytes.len() != 32 {
    return Err(Error::from_reason("Key must be 32 bytes long"));
  }

  let cipher =
    XChaCha20Poly1305::new_from_slice(key_bytes).map_err(|_| Error::from_reason("Invalid key"))?;

  let nonce =
    XNonce::try_from(nonce_bytes).map_err(|_| Error::from_reason("Invalid nonce length"))?;

  let plaintext: Vec<u8> = cipher
    .decrypt(&nonce, payload_bytes)
    .map_err(|_| Error::from_reason("Decryption failed (bad tag or key)"))?;

  Ok(Uint8Array::from(plaintext))
}

#[napi]
pub fn generate_one_time_keys(
  length: KemLength,
  qty: i32,
  account_name: String,
  prefix: String,
) -> napi::Result<Vec<OneTimeKey>> {
  let algorithm: &'static Algorithm = match length {
    KemLength::MlKem1024 => &ML_KEM_1024,
    KemLength::MlKem768 => &ML_KEM_768,
    KemLength::MlKem512 => &ML_KEM_512,
  };

  let mut one_time_keys: Vec<OneTimeKey> = Vec::with_capacity(qty as usize);
  let mut i: i32 = 0;

  while i < qty {
    let mut key_id_bytes = [0u8; 4];
    rand::fill(&mut key_id_bytes).map_err(|_| Error::from_reason("Random generation failed"))?;
    let key_id: String = hex_encode(key_id_bytes);

    let decapsulation_key: DecapsulationKey = DecapsulationKey::generate(algorithm)
      .map_err(|_| Error::from_reason("Failed to generate pair keys"))?;
    let encapsulation_key: EncapsulationKey = decapsulation_key
      .encapsulation_key()
      .map_err(|_| Error::from_reason("Failed to generate private key"))?;

    let pub_key_bytes: EncapsulationKeyBytes = encapsulation_key
      .key_bytes()
      .map_err(|_| Error::from_reason("Failed convert public key to bytes"))?;

    let private_key_bytes: DecapsulationKeyBytes = decapsulation_key
      .key_bytes()
      .map_err(|_| Error::from_reason("Failed convert private key to bytes"))?;

    let private_key = Uint8Array::from(private_key_bytes.as_ref());
    let public_key = Uint8Array::from(pub_key_bytes.as_ref());

    let secret_name: String = format!("{}-otk-{}", prefix, key_id);
    let account_name: String = format!("gluechat_{}", account_name);

    one_time_keys.push(OneTimeKey {
      account_name,
      secret_name,
      id: key_id,
      pub_key: public_key,
      private_key,
    });

    i += 1;
  }

  Ok(one_time_keys)
}

#[napi]
pub fn kem_keypair(length: KemLength) -> napi::Result<KEMKeyPair> {
  let algorithm: &'static Algorithm = match length {
    KemLength::MlKem1024 => &ML_KEM_1024,
    KemLength::MlKem768 => &ML_KEM_768,
    KemLength::MlKem512 => &ML_KEM_512,
  };
  let decapsulation_key: DecapsulationKey = DecapsulationKey::generate(algorithm)
    .map_err(|_| Error::from_reason("Failed to generate pair keys"))?;

  let encapsulation_key: EncapsulationKey = decapsulation_key
    .encapsulation_key()
    .map_err(|_| Error::from_reason("Failed to generate encapsulation key"))?;

  let pub_key_bytes: EncapsulationKeyBytes = encapsulation_key
    .key_bytes()
    .map_err(|_| Error::from_reason("Failed to convert public key to bytes"))?;

  let private_key_bytes: DecapsulationKeyBytes = decapsulation_key
    .key_bytes()
    .map_err(|_| Error::from_reason("Failed to convert private key to bytes"))?;

  let private_key = Uint8Array::from(private_key_bytes.as_ref());
  let public_key = Uint8Array::from(pub_key_bytes.as_ref());

  Ok(KEMKeyPair {
    private_key,
    public_key,
  })
}
