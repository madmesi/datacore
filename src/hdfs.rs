use arrow::record_batch::RecordBatch;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use crate::kms::{CryptoMetadataHeader, HadoopKmsEngine};

#[derive(Error, Debug)]
pub enum HdfsError {
    #[error("Network I/O error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("HDFS API error (status {0}): {1}")]
    Api(StatusCode, String),
    #[error("Parquet encode/decode error: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),
    #[error("File not found: {0}")]
    NotFound(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileStatus {
    pub path: String,
    pub length: u64,
    pub modification_time: u64,
    pub replication: u16,
    pub block_size: u64,
    pub owner: String,
    pub group: String,
    pub permission: String,
    pub file_type: String,
}

#[derive(Clone)]
pub struct WebHdfsClient {
    namenode_url: String,
    super_user: String,
    http_client: Client,
    local_cluster_vfs: Arc<RwLock<HashMap<String, (Vec<u8>, String)>>>,
    xattr_crypto_storage: Arc<RwLock<HashMap<String, CryptoMetadataHeader>>>,
    pub kms: Arc<HadoopKmsEngine>,
    allowed_proxy_groups: Vec<String>,
}

impl WebHdfsClient {
    pub fn new(namenode_url: &str, super_user: &str) -> Self {
        let http_client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let kms = Arc::new(HadoopKmsEngine::new());
        let mut initial_vfs = HashMap::new();
        initial_vfs.insert(
            "/warehouse/analytics/cluster_events/metadata/v1.metadata.json".to_string(),
            (
                br#"{"format-version":2,"table-uuid":"4a8167f8-3e4b-4bcf-a5dc-87c26027c62b","location":"/warehouse/analytics/cluster_events"}"#.to_vec(),
                "admin".to_string(),
            ),
        );

        Self {
            namenode_url: namenode_url.trim_end_matches('/').to_string(),
            super_user: super_user.to_string(),
            http_client,
            local_cluster_vfs: Arc::new(RwLock::new(initial_vfs)),
            xattr_crypto_storage: Arc::new(RwLock::new(HashMap::new())),
            kms,
            allowed_proxy_groups: vec!["data-engineers".to_string(), "analytics".to_string(), "admins".to_string()],
        }
    }

    fn build_query_params(&self, op: &str, do_as_user: Option<&str>, extra_args: &str) -> String {
        let mut query = format!("op={}&user.name={}", op, self.super_user);
        if let Some(user) = do_as_user {
            query.push_str(&format!("&doAs={user}"));
        }
        if !extra_args.is_empty() {
            query.push('&');
            query.push_str(extra_args);
        }
        query
    }

    pub async fn write_file_as(
        &self,
        path: &str,
        data: Vec<u8>,
        _overwrite: bool,
        do_as_user: Option<&str>,
    ) -> Result<String, HdfsError> {
        let clean_path = path.trim_start_matches('/');
        let effective_owner = do_as_user.unwrap_or(&self.super_user).to_string();

        let (payload_to_store, crypto_header) = if let Some(ez) = self.kms.get_encryption_zone_for_path(path).await {
            let (raw_dek, eek) = self.kms.generate_edek(&ez.key_name).await
                .map_err(|e| HdfsError::Api(StatusCode::INTERNAL_SERVER_ERROR, format!("KMS error: {e}")))?;

            let iv_bytes = (0..eek.iv.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&eek.iv[i..i+2], 16).unwrap_or(0))
                .collect::<Vec<u8>>();

            let ciphertext = HadoopKmsEngine::encrypt_payload(&data, &raw_dek, &iv_bytes)
                .map_err(|e| HdfsError::Api(StatusCode::INTERNAL_SERVER_ERROR, format!("Cipher error: {e}")))?;

            let header = CryptoMetadataHeader {
                ez_key_name: ez.key_name,
                ez_key_version: eek.key_version,
                iv_hex: eek.iv,
                edek_hex: eek.edek,
            };

            (ciphertext, Some(header))
        } else {
            (data, None)
        };

        let mut vfs = self.local_cluster_vfs.write().await;
        vfs.insert(format!("/{clean_path}"), (payload_to_store, effective_owner));

        if let Some(hdr) = crypto_header {
            let mut xattrs = self.xattr_crypto_storage.write().await;
            xattrs.insert(format!("/{clean_path}"), hdr);
        }

        Ok(format!("hdfs:///{}", clean_path))
    }

    pub async fn read_file_as(&self, path: &str, _do_as_user: Option<&str>) -> Result<Vec<u8>, HdfsError> {
        let clean_path = path.trim_start_matches('/');
        let full_path = format!("/{clean_path}");

        let (raw_stored_bytes, _) = {
            let vfs = self.local_cluster_vfs.read().await;
            vfs.get(&full_path).cloned().ok_or_else(|| HdfsError::NotFound(full_path.clone()))?
        };

        let xattrs = self.xattr_crypto_storage.read().await;
        if let Some(hdr) = xattrs.get(&full_path) {
            let raw_dek = self.kms.decrypt_edek(
                &hdr.ez_key_name,
                &hdr.ez_key_version,
                &hdr.iv_hex,
                &hdr.edek_hex,
            ).await.map_err(|e| HdfsError::Api(StatusCode::INTERNAL_SERVER_ERROR, format!("KMS decrypt failed: {e}")))?;

            let iv_bytes = (0..hdr.iv_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hdr.iv_hex[i..i+2], 16).unwrap_or(0))
                .collect::<Vec<u8>>();

            let plaintext = HadoopKmsEngine::decrypt_payload(&raw_stored_bytes, &raw_dek, &iv_bytes)
                .map_err(|e| HdfsError::Api(StatusCode::INTERNAL_SERVER_ERROR, format!("Cipher decrypt failed: {e}")))?;

            Ok(plaintext)
        } else {
            Ok(raw_stored_bytes)
        }
    }

    pub async fn write_parquet_as(
        &self,
        path: &str,
        batch: &RecordBatch,
        overwrite: bool,
        do_as_user: Option<&str>,
    ) -> Result<usize, HdfsError> {
        let mut buffer = Vec::new();
        {
            let mut writer = ArrowWriter::try_new(&mut buffer, batch.schema(), None)?;
            writer.write(batch)?;
            writer.close()?;
        }

        let byte_len = buffer.len();
        self.write_file_as(path, buffer, overwrite, do_as_user).await?;
        Ok(byte_len)
    }

    pub async fn read_parquet_as(&self, path: &str, do_as_user: Option<&str>) -> Result<Vec<RecordBatch>, HdfsError> {
        let parquet_bytes = self.read_file_as(path, do_as_user).await?;
        let bytes_data = bytes::Bytes::from(parquet_bytes);
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes_data)?.build()?;

        let mut batches = Vec::new();
        for batch_result in reader {
            batches.push(batch_result?);
        }

        Ok(batches)
    }

    pub async fn delete_file_as(&self, path: &str, _recursive: bool, _do_as_user: Option<&str>) -> Result<bool, HdfsError> {
        let clean_path = path.trim_start_matches('/');
        let mut vfs = self.local_cluster_vfs.write().await;
        let removed = vfs.remove(&format!("/{clean_path}")).is_some();
        let mut xattrs = self.xattr_crypto_storage.write().await;
        xattrs.remove(&format!("/{clean_path}"));
        Ok(removed)
    }

    pub async fn list_status(&self) -> Vec<FileStatus> {
        let vfs = self.local_cluster_vfs.read().await;
        vfs.iter()
            .map(|(path, (bytes, owner))| FileStatus {
                path: path.clone(),
                length: bytes.len() as u64,
                modification_time: chrono::Utc::now().timestamp_millis() as u64,
                replication: 3,
                block_size: 134217728,
                owner: owner.clone(),
                group: "analytics".to_string(),
                permission: "750".to_string(),
                file_type: "FILE".to_string(),
            })
            .collect()
    }

    pub async fn list_prefix(&self, prefix: &str) -> Vec<String> {
        let vfs = self.local_cluster_vfs.read().await;
        vfs.keys().filter(|k| k.starts_with(prefix)).cloned().collect()
    }

    pub async fn reencrypt_zone_edeks(&self, zone_path: &str) -> Result<crate::kms::ReencryptionSummary, HdfsError> {
        let ez = self
            .kms
            .get_encryption_zone_for_path(zone_path)
            .await
            .ok_or_else(|| HdfsError::NotFound(format!("Encryption zone for path '{zone_path}' not found")))?;

        let latest_key = self.kms.get_latest_key(&ez.key_name).await
            .map_err(|e| HdfsError::Api(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let mut xattrs = self.xattr_crypto_storage.write().await;
        let mut reencrypted_files = Vec::new();

        for (file_path, hdr) in xattrs.iter_mut() {
            if file_path.starts_with(zone_path) && hdr.ez_key_version != latest_key.version {
                let updated_hdr = self.kms.reencrypt_single_edek(hdr).await
                    .map_err(|e| HdfsError::Api(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                *hdr = updated_hdr;
                reencrypted_files.push(file_path.clone());
            }
        }

        Ok(crate::kms::ReencryptionSummary {
            zone_path: zone_path.to_string(),
            key_name: ez.key_name,
            target_version: latest_key.version,
            reencrypted_files_count: reencrypted_files.len(),
            reencrypted_files,
        })
    }

    pub async fn get_crypto_header(&self, path: &str) -> Option<CryptoMetadataHeader> {
        let clean_path = format!("/{}", path.trim_start_matches('/'));
        let xattrs = self.xattr_crypto_storage.read().await;
        xattrs.get(&clean_path).cloned()
    }

    pub async fn write_file(&self, path: &str, data: Vec<u8>, overwrite: bool) -> Result<String, HdfsError> {
        self.write_file_as(path, data, overwrite, None).await
    }

    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>, HdfsError> {
        self.read_file_as(path, None).await
    }

    pub async fn write_parquet(&self, path: &str, batch: &RecordBatch, overwrite: bool) -> Result<usize, HdfsError> {
        self.write_parquet_as(path, batch, overwrite, None).await
    }

    pub async fn read_parquet(&self, path: &str) -> Result<Vec<RecordBatch>, HdfsError> {
        self.read_parquet_as(path, None).await
    }

    pub async fn delete_file(&self, path: &str, recursive: bool) -> Result<bool, HdfsError> {
        self.delete_file_as(path, recursive, None).await
    }
}
