use aes::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

#[derive(Error, Debug)]
pub enum KmsError {
    #[error("Encryption zone key '{0}' not found in KMS")]
    KeyNotFound(String),
    #[error("Key version '{0}' for key '{1}' not found")]
    KeyVersionNotFound(String, String),
    #[error("Crypto cipher error: {0}")]
    CipherError(String),
    #[error("Invalid key or IV length: expected {0} bytes")]
    InvalidKeyLength(usize),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionZoneConfig {
    pub zone_path: String,
    pub key_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MasterKeyEntry {
    pub key_name: String,
    pub version: String,
    pub cipher: String,
    pub length: u32,
    pub created_time_ms: i64,
    #[serde(skip_serializing)]
    pub master_key_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedKeyVersion {
    pub key_name: String,
    pub key_version: String,
    pub iv: String,
    pub edek: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoMetadataHeader {
    pub ez_key_name: String,
    pub ez_key_version: String,
    pub iv_hex: String,
    pub edek_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReencryptionSummary {
    pub zone_path: String,
    pub key_name: String,
    pub target_version: String,
    pub reencrypted_files_count: usize,
    pub reencrypted_files: Vec<String>,
}

pub struct HadoopKmsEngine {
    key_versions: Arc<RwLock<HashMap<String, Vec<MasterKeyEntry>>>>,
    encryption_zones: Arc<RwLock<HashMap<String, EncryptionZoneConfig>>>,
}

impl HadoopKmsEngine {
    pub fn new() -> Self {
        let mut key_versions = HashMap::new();
        let mut encryption_zones = HashMap::new();

        let ez_key_name = "ez-analytics-key".to_string();
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);

        let initial_v1 = MasterKeyEntry {
            key_name: ez_key_name.clone(),
            version: "v1".to_string(),
            cipher: "AES/CTR/NoPadding".to_string(),
            length: 256,
            created_time_ms: chrono::Utc::now().timestamp_millis(),
            master_key_bytes: key_bytes.to_vec(),
        };

        key_versions.insert(ez_key_name.clone(), vec![initial_v1]);

        encryption_zones.insert(
            "/warehouse/analytics".to_string(),
            EncryptionZoneConfig {
                zone_path: "/warehouse/analytics".to_string(),
                key_name: ez_key_name,
            },
        );

        Self {
            key_versions: Arc::new(RwLock::new(key_versions)),
            encryption_zones: Arc::new(RwLock::new(encryption_zones)),
        }
    }

    pub async fn get_encryption_zone_for_path(&self, path: &str) -> Option<EncryptionZoneConfig> {
        let zones = self.encryption_zones.read().await;
        for (zone_prefix, config) in zones.iter() {
            if path.starts_with(zone_prefix) {
                return Some(config.clone());
            }
        }
        None
    }

    pub async fn roll_new_master_key_version(&self, key_name: &str) -> Result<MasterKeyEntry, KmsError> {
        let mut kv_map = self.key_versions.write().await;
        let versions = kv_map
            .get_mut(key_name)
            .ok_or_else(|| KmsError::KeyNotFound(key_name.to_string()))?;

        let next_v_num = versions.len() + 1;
        let new_version = format!("v{next_v_num}");

        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);

        let new_entry = MasterKeyEntry {
            key_name: key_name.to_string(),
            version: new_version,
            cipher: "AES/CTR/NoPadding".to_string(),
            length: 256,
            created_time_ms: chrono::Utc::now().timestamp_millis(),
            master_key_bytes: key_bytes.to_vec(),
        };

        versions.push(new_entry.clone());
        Ok(new_entry)
    }

    pub async fn get_latest_key(&self, key_name: &str) -> Result<MasterKeyEntry, KmsError> {
        let kv_map = self.key_versions.read().await;
        kv_map
            .get(key_name)
            .and_then(|v| v.last())
            .cloned()
            .ok_or_else(|| KmsError::KeyNotFound(key_name.to_string()))
    }

    pub async fn get_specific_key_version(&self, key_name: &str, version: &str) -> Result<MasterKeyEntry, KmsError> {
        let kv_map = self.key_versions.read().await;
        let versions = kv_map
            .get(key_name)
            .ok_or_else(|| KmsError::KeyNotFound(key_name.to_string()))?;

        versions
            .iter()
            .find(|k| k.version == version)
            .cloned()
            .ok_or_else(|| KmsError::KeyVersionNotFound(version.to_string(), key_name.to_string()))
    }

    pub async fn generate_edek(&self, key_name: &str) -> Result<(Vec<u8>, EncryptedKeyVersion), KmsError> {
        let master = self.get_latest_key(key_name).await?;

        let mut raw_dek = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw_dek);

        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        let mut cipher = Aes256Ctr::new(
            master.master_key_bytes.as_slice().into(),
            (&iv).into(),
        );
        let mut edek_bytes = raw_dek;
        cipher.apply_keystream(&mut edek_bytes);

        let eek = EncryptedKeyVersion {
            key_name: key_name.to_string(),
            key_version: master.version,
            iv: iv.iter().map(|b| format!("{b:02x}")).collect(),
            edek: edek_bytes.iter().map(|b| format!("{b:02x}")).collect(),
        };

        Ok((raw_dek.to_vec(), eek))
    }

    pub async fn decrypt_edek(&self, key_name: &str, version: &str, iv_hex: &str, edek_hex: &str) -> Result<Vec<u8>, KmsError> {
        let master = self.get_specific_key_version(key_name, version).await?;

        let iv = (0..iv_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&iv_hex[i..i + 2], 16).unwrap_or(0))
            .collect::<Vec<u8>>();

        let edek = (0..edek_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&edek_hex[i..i + 2], 16).unwrap_or(0))
            .collect::<Vec<u8>>();

        if iv.len() != 16 || edek.len() != 32 {
            return Err(KmsError::InvalidKeyLength(32));
        }

        let mut cipher = Aes256Ctr::new(
            master.master_key_bytes.as_slice().into(),
            iv.as_slice().into(),
        );

        let mut raw_dek = edek;
        cipher.apply_keystream(&mut raw_dek);

        Ok(raw_dek)
    }

    pub async fn reencrypt_single_edek(
        &self,
        current_hdr: &CryptoMetadataHeader,
    ) -> Result<CryptoMetadataHeader, KmsError> {
        let latest_master = self.get_latest_key(&current_hdr.ez_key_name).await?;

        if current_hdr.ez_key_version == latest_master.version {
            return Ok(current_hdr.clone());
        }

        let raw_dek = self
            .decrypt_edek(
                &current_hdr.ez_key_name,
                &current_hdr.ez_key_version,
                &current_hdr.iv_hex,
                &current_hdr.edek_hex,
            )
            .await?;

        let mut new_iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut new_iv);

        let mut cipher = Aes256Ctr::new(
            latest_master.master_key_bytes.as_slice().into(),
            (&new_iv).into(),
        );
        let mut new_edek_bytes = [0u8; 32];
        new_edek_bytes.copy_from_slice(&raw_dek);
        cipher.apply_keystream(&mut new_edek_bytes);

        Ok(CryptoMetadataHeader {
            ez_key_name: current_hdr.ez_key_name.clone(),
            ez_key_version: latest_master.version,
            iv_hex: new_iv.iter().map(|b| format!("{b:02x}")).collect(),
            edek_hex: new_edek_bytes.iter().map(|b| format!("{b:02x}")).collect(),
        })
    }

    pub fn encrypt_payload(raw_data: &[u8], dek: &[u8], iv: &[u8]) -> Result<Vec<u8>, KmsError> {
        if dek.len() != 32 || iv.len() != 16 {
            return Err(KmsError::InvalidKeyLength(32));
        }
        let mut cipher = Aes256Ctr::new(dek.into(), iv.into());
        let mut ciphertext = raw_data.to_vec();
        cipher.apply_keystream(&mut ciphertext);
        Ok(ciphertext)
    }

    pub fn decrypt_payload(ciphertext: &[u8], dek: &[u8], iv: &[u8]) -> Result<Vec<u8>, KmsError> {
        Self::encrypt_payload(ciphertext, dek, iv)
    }

    pub async fn list_zones(&self) -> Vec<EncryptionZoneConfig> {
        let zones = self.encryption_zones.read().await;
        zones.values().cloned().collect()
    }

    pub async fn list_all_key_versions(&self) -> Vec<MasterKeyEntry> {
        let kv = self.key_versions.read().await;
        kv.values().flatten().cloned().collect()
    }
}
