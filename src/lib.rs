use aws_lc_rs::kem::{
  Algorithm, Ciphertext, DecapsulationKey, DecapsulationKeyBytes, EncapsulationKey,
  EncapsulationKeyBytes, ML_KEM_1024, ML_KEM_512, ML_KEM_768,
};

use aws_lc_rs::encoding::{AsDer, AsRawBytes};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
  KeyPair, PqdsaKeyPair, PqdsaSigningAlgorithm, UnparsedPublicKey, ML_DSA_44_SIGNING,
  ML_DSA_65_SIGNING, ML_DSA_87_SIGNING,
};
use aws_lc_rs::{rand, signature};
use chacha20poly1305::{
  aead::{Aead, KeyInit},
  XChaCha20Poly1305, XNonce,
};
use napi::bindgen_prelude::Uint8Array;
use napi::Error;
use napi_derive::napi;

use base64::engine::general_purpose;
use base64::Engine;
use hex::encode as hex_encode;

#[napi(object)]
pub struct KEMKeyPair {
  pub private_key: String,
  pub public_key: String,
}

#[napi(object)]
pub struct OneTimeKey {
  pub account_name: String,
  pub secret_name: String,
  pub id: String,
  pub pub_key: String,
  pub private_key: String,
}

#[napi(object)]
pub struct EncapsulationResult {
  pub ciphertext: String,
  pub shared_secret: String,
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

#[napi]
pub struct DSAKeyPair {
  pub private_key: String,
  pub public_key: String,
}

#[napi]
pub fn ml_dsa_keypair(length: MlDsaLength) -> napi::Result<DSAKeyPair> {
  let algorithm = match length {
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

  let private_key = general_purpose::STANDARD.encode(private_key_bytes.as_ref());
  let public_key = general_purpose::STANDARD.encode(public_key_bytes);

  Ok(DSAKeyPair {
    private_key,
    public_key,
  })
}

#[napi]
pub fn encapsulate(
  length: KemLength,
  public_key_base64: String,
) -> napi::Result<EncapsulationResult> {
  let algorithm: &'static Algorithm = match length {
    KemLength::MlKem1024 => &ML_KEM_1024,
    KemLength::MlKem768 => &ML_KEM_768,
    KemLength::MlKem512 => &ML_KEM_512,
  };

  let pub_key_bytes = general_purpose::STANDARD
    .decode(&public_key_base64)
    .map_err(|e| Error::from_reason(format!("Invalid public key base64: {e}")))?;

  let enc_key = EncapsulationKey::new(algorithm, &pub_key_bytes)
    .map_err(|_| Error::from_reason("Invalid public key bytes"))?;

  let (ciphertext_bytes, shared_secret) = enc_key
    .encapsulate()
    .map_err(|_| Error::from_reason("Encapsulation failed"))?;

  Ok(EncapsulationResult {
    ciphertext: general_purpose::STANDARD.encode(ciphertext_bytes.as_ref()),
    shared_secret: general_purpose::STANDARD.encode(shared_secret.as_ref()),
  })
}

#[napi]
pub fn decapsulate(
  length: KemLength,
  private_key_base64: String,
  ciphertext_base64: String,
) -> napi::Result<String> {
  let algorithm: &'static Algorithm = match length {
    KemLength::MlKem1024 => &ML_KEM_1024,
    KemLength::MlKem768 => &ML_KEM_768,
    KemLength::MlKem512 => &ML_KEM_512,
  };

  let priv_key_bytes = general_purpose::STANDARD
    .decode(&private_key_base64)
    .map_err(|e| Error::from_reason(format!("Invalid private key base64: {e}")))?;

  let ciphertext_bytes = general_purpose::STANDARD
    .decode(&ciphertext_base64)
    .map_err(|e| Error::from_reason(format!("Invalid ciphertext base64: {e}")))?;

  let dec_key = DecapsulationKey::new(algorithm, &priv_key_bytes)
    .map_err(|_| Error::from_reason("Invalid private key bytes"))?;

  let ciphertext = Ciphertext::from(ciphertext_bytes.as_slice());

  let shared_secret = dec_key
    .decapsulate(ciphertext)
    .map_err(|_| Error::from_reason("Decapsulation failed"))?;

  Ok(general_purpose::STANDARD.encode(shared_secret.as_ref()))
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
pub fn encrypt(plaintext: String, key: String) -> napi::Result<String> {
  let key_bytes: Vec<u8> = general_purpose::STANDARD
    .decode(&key)
    .map_err(|e| Error::from_reason(format!("Invalid key base64: {e}")))?;

  if key_bytes.len() != 32 {
    return Err(Error::from_reason("Key must be 32 bytes long"));
  }

  let cipher =
    XChaCha20Poly1305::new_from_slice(&key_bytes).map_err(|_| Error::from_reason("Invalid key"))?;

  let mut nonce_bytes: [u8; 24] = [0u8; 24];
  rand::fill(&mut nonce_bytes).map_err(|_| Error::from_reason("Random generation failed"))?;
  let nonce = XNonce::try_from(nonce_bytes.as_slice())
    .map_err(|_| Error::from_reason("Invalid nonce length"))?;

  let ciphertext: Vec<u8> = cipher
    .encrypt(&nonce, plaintext.as_bytes())
    .map_err(|_| Error::from_reason("Encryption failed"))?;

  let ciphertext_base64: String = general_purpose::STANDARD.encode(&ciphertext);
  let nonce_base64: String = general_purpose::STANDARD.encode(nonce_bytes);

  Ok(format!("{ciphertext_base64}::{nonce_base64}"))
}

#[napi]
pub fn decrypt(ciphertext: String, key: String) -> napi::Result<String> {
  let parts: Vec<&str> = ciphertext.split("::").collect();
  if parts.len() != 2 {
    return Err(Error::from_reason(
      "Invalid ciphertext format. Expected payload::nonce",
    ));
  }

  let ciphertext_bytes: Vec<u8> = general_purpose::STANDARD
    .decode(parts[0])
    .map_err(|e| Error::from_reason(format!("Invalid ciphertext base64: {e}")))?;

  let nonce_bytes: Vec<u8> = general_purpose::STANDARD
    .decode(parts[1])
    .map_err(|e| Error::from_reason(format!("Invalid nonce base64: {e}")))?;

  if nonce_bytes.len() != 24 {
    return Err(Error::from_reason("Nonce must be 24 bytes long"));
  }

  let key_bytes: Vec<u8> = general_purpose::STANDARD
    .decode(&key)
    .map_err(|e| Error::from_reason(format!("Invalid key base64: {e}")))?;

  if key_bytes.len() != 32 {
    return Err(Error::from_reason("Key must be 32 bytes long"));
  }

  let cipher =
    XChaCha20Poly1305::new_from_slice(&key_bytes).map_err(|_| Error::from_reason("Invalid key"))?;

  let nonce = XNonce::try_from(nonce_bytes.as_slice())
    .map_err(|_| Error::from_reason("Invalid nonce length"))?;

  let plaintext: Vec<u8> = cipher
    .decrypt(&nonce, ciphertext_bytes.as_ref())
    .map_err(|_| Error::from_reason("Decryption failed (bad tag or key)"))?;

  String::from_utf8(plaintext)
    .map_err(|e| Error::from_reason(format!("Invalid UTF-8 plaintext: {e}")))
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

    let private_key: String = general_purpose::STANDARD.encode(private_key_bytes.as_ref());
    let public_key: String = general_purpose::STANDARD.encode(pub_key_bytes.as_ref());

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

  let private_key: String = general_purpose::STANDARD.encode(private_key_bytes.as_ref());
  let public_key: String = general_purpose::STANDARD.encode(pub_key_bytes.as_ref());

  Ok(KEMKeyPair {
    private_key,
    public_key,
  })
}
