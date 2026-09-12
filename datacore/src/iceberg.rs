use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::hdfs::WebHdfsClient;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NestedField {
    pub id: i32,
    pub name: String,
    pub required: bool,
    pub field_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TableSchema {
    pub schema_id: i32,
    pub fields: Vec<NestedField>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub snapshot_id: i64,
    pub parent_snapshot_id: Option<i64>,
    pub timestamp_ms: i64,
    pub manifest_list: String,
    pub summary: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TableMetadata {
    pub format_version: i32,
    pub table_uuid: String,
    pub location: String,
    pub last_updated_ms: i64,
    pub current_snapshot_id: Option<i64>,
    pub schemas: Vec<TableSchema>,
    pub current_schema_id: i32,
    pub snapshots: Vec<Snapshot>,
    pub metadata_version: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestFileEntry {
    pub file_path: String,
    pub file_format: String,
    pub record_count: i64,
    pub file_size_in_bytes: i64,
    pub partition_values: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanupReport {
    pub table_name: String,
    pub expired_snapshots_count: usize,
    pub expired_snapshot_ids: Vec<i64>,
    pub deleted_manifest_files: Vec<String>,
    pub deleted_orphan_parquet_files: Vec<String>,
    pub reclaimed_bytes: u64,
    pub new_metadata_version: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactionReport {
    pub table_name: String,
    pub compacted_partitions: Vec<String>,
    pub files_merged_count: usize,
    pub original_bytes: u64,
    pub compacted_bytes: u64,
    pub new_file_path: String,
    pub new_snapshot_id: i64,
}

pub struct IcebergCatalog {
    tables: RwLock<HashMap<String, TableMetadata>>,
    manifests: RwLock<HashMap<String, Vec<ManifestFileEntry>>>,
    hdfs: Arc<WebHdfsClient>,
}

impl IcebergCatalog {
    pub fn new(hdfs: Arc<WebHdfsClient>) -> Self {
        let mut tables = HashMap::new();
        let mut manifests = HashMap::new();

        let table_uuid = uuid::Uuid::new_v4().to_string();
        let current_snapshot_id = 894723947293847291;
        let manifest_list_path = "/warehouse/analytics/cluster_events/metadata/snap-894723947293847291.avro";

        let schema = TableSchema {
            schema_id: 0,
            fields: vec![
                NestedField {
                    id: 1,
                    name: "event_id".to_string(),
                    required: true,
                    field_type: "long".to_string(),
                },
                NestedField {
                    id: 2,
                    name: "timestamp".to_string(),
                    required: true,
                    field_type: "timestamptz".to_string(),
                },
                NestedField {
                    id: 3,
                    name: "service_name".to_string(),
                    required: true,
                    field_type: "string".to_string(),
                },
                NestedField {
                    id: 4,
                    name: "cpu_usage".to_string(),
                    required: false,
                    field_type: "double".to_string(),
                },
            ],
        };

        let mut summary = HashMap::new();
        summary.insert("operation".to_string(), "append".to_string());
        summary.insert("added-records".to_string(), "15420".to_string());
        summary.insert("spark.app.id".to_string(), "app-2026-spark-0012".to_string());

        let snapshot = Snapshot {
            snapshot_id: current_snapshot_id,
            parent_snapshot_id: None,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            manifest_list: manifest_list_path.to_string(),
            summary,
        };

        let metadata = TableMetadata {
            format_version: 2,
            table_uuid,
            location: "/warehouse/analytics/cluster_events".to_string(),
            last_updated_ms: chrono::Utc::now().timestamp_millis(),
            current_snapshot_id: Some(current_snapshot_id),
            schemas: vec![schema],
            current_schema_id: 0,
            snapshots: vec![snapshot],
            metadata_version: 1,
        };

        tables.insert("analytics.cluster_events".to_string(), metadata);

        let file_entries = vec![
            ManifestFileEntry {
                file_path: "/warehouse/analytics/cluster_events/data/part-00000.parquet".to_string(),
                file_format: "PARQUET".to_string(),
                record_count: 7710,
                file_size_in_bytes: 482910,
                partition_values: [("dt".to_string(), "2026-09-12".to_string())].into(),
            },
            ManifestFileEntry {
                file_path: "/warehouse/analytics/cluster_events/data/part-00001.parquet".to_string(),
                file_format: "PARQUET".to_string(),
                record_count: 7710,
                file_size_in_bytes: 491024,
                partition_values: [("dt".to_string(), "2026-09-12".to_string())].into(),
            },
        ];
        manifests.insert(manifest_list_path.to_string(), file_entries);

        Self {
            tables: RwLock::new(tables),
            manifests: RwLock::new(manifests),
            hdfs,
        }
    }

    pub async fn list_tables(&self) -> Vec<String> {
        let tables = self.tables.read().await;
        tables.keys().cloned().collect()
    }

    pub async fn get_table(&self, table_name: &str) -> Option<TableMetadata> {
        let tables = self.tables.read().await;
        tables.get(table_name).cloned()
    }

    pub async fn get_manifest_files(&self, manifest_list: &str) -> Vec<ManifestFileEntry> {
        let manifests = self.manifests.read().await;
        manifests.get(manifest_list).cloned().unwrap_or_default()
    }

    pub async fn commit_snapshot_to_hdfs(
        &self,
        table_name: &str,
        new_files: Vec<ManifestFileEntry>,
        operation: &str,
    ) -> Result<Snapshot, String> {
        let mut tables = self.tables.write().await;
        let mut manifests = self.manifests.write().await;

        let table = tables
            .get_mut(table_name)
            .ok_or_else(|| format!("Table '{table_name}' not found in catalog"))?;

        let parent_snapshot = table.current_snapshot_id;
        let new_snapshot_id = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let now_ms = chrono::Utc::now().timestamp_millis();
        let total_added_records: i64 = new_files.iter().map(|f| f.record_count).sum();

        let manifest_filename = format!("{}/metadata/snap-{}.avro", table.location, new_snapshot_id);
        let next_meta_version = table.metadata_version + 1;
        let metadata_filename = format!("{}/metadata/v{}.metadata.json", table.location, next_meta_version);

        let manifest_json = serde_json::to_vec_pretty(&new_files)
            .map_err(|e| format!("Failed to serialize manifest: {e}"))?;
        self.hdfs
            .write_file(&manifest_filename, manifest_json, true)
            .await
            .map_err(|e| format!("WebHDFS failed writing manifest: {e}"))?;

        let mut summary = HashMap::new();
        summary.insert("operation".to_string(), operation.to_string());
        summary.insert("added-records".to_string(), total_added_records.to_string());
        summary.insert("added-data-files".to_string(), new_files.len().to_string());
        summary.insert("engine".to_string(), "datacore-rust-v0.1".to_string());

        let snapshot = Snapshot {
            snapshot_id: new_snapshot_id,
            parent_snapshot_id: parent_snapshot,
            timestamp_ms: now_ms,
            manifest_list: manifest_filename.clone(),
            summary,
        };

        table.snapshots.push(snapshot.clone());
        table.current_snapshot_id = Some(new_snapshot_id);
        table.last_updated_ms = now_ms;
        table.metadata_version = next_meta_version;

        let table_meta_bytes = serde_json::to_vec_pretty(&table)
            .map_err(|e| format!("Failed to serialize table metadata: {e}"))?;

        self.hdfs
            .write_file(&metadata_filename, table_meta_bytes, true)
            .await
            .map_err(|e| format!("WebHDFS failed writing v{next_meta_version}.metadata.json: {e}"))?;

        manifests.insert(manifest_filename, new_files);

        Ok(snapshot)
    }

    pub async fn expire_snapshots_and_clean_orphans(
        &self,
        table_name: &str,
        retain_last_n: usize,
        max_age_ms: i64,
    ) -> Result<CleanupReport, String> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cutoff_time = now_ms - max_age_ms;

        let mut tables = self.tables.write().await;
        let mut manifests = self.manifests.write().await;

        let table = tables
            .get_mut(table_name)
            .ok_or_else(|| format!("Table '{table_name}' not found"))?;

        if table.snapshots.len() <= retain_last_n {
            return Ok(CleanupReport {
                table_name: table_name.to_string(),
                expired_snapshots_count: 0,
                expired_snapshot_ids: vec![],
                deleted_manifest_files: vec![],
                deleted_orphan_parquet_files: vec![],
                reclaimed_bytes: 0,
                new_metadata_version: table.metadata_version,
            });
        }

        let total_snapshots = table.snapshots.len();
        let split_idx = total_snapshots.saturating_sub(retain_last_n);

        let mut retained_snapshots = Vec::new();
        let mut expired_snapshots = Vec::new();

        for (idx, snap) in table.snapshots.iter().enumerate() {
            if idx < split_idx && snap.timestamp_ms < cutoff_time {
                expired_snapshots.push(snap.clone());
            } else {
                retained_snapshots.push(snap.clone());
            }
        }

        let expired_ids: Vec<i64> = expired_snapshots.iter().map(|s| s.snapshot_id).collect();

        let mut active_manifest_lists = std::collections::HashSet::new();
        let mut active_parquet_data_files = std::collections::HashSet::new();

        for snap in &retained_snapshots {
            active_manifest_lists.insert(snap.manifest_list.clone());
            if let Some(entries) = manifests.get(&snap.manifest_list) {
                for file_entry in entries {
                    active_parquet_data_files.insert(file_entry.file_path.clone());
                }
            }
        }

        let mut deleted_manifests = Vec::new();
        for snap in &expired_snapshots {
            if !active_manifest_lists.contains(&snap.manifest_list) {
                let _ = self.hdfs.delete_file(&snap.manifest_list, false).await;
                manifests.remove(&snap.manifest_list);
                deleted_manifests.push(snap.manifest_list.clone());
            }
        }

        let data_prefix = format!("{}/data", table.location);
        let physical_files = self.hdfs.list_prefix(&data_prefix).await;

        let mut deleted_orphans = Vec::new();
        let mut reclaimed_bytes: u64 = 0;

        for hdfs_file in physical_files {
            if hdfs_file.ends_with(".parquet") && !active_parquet_data_files.contains(&hdfs_file) {
                if let Ok(bytes) = self.hdfs.read_file(&hdfs_file).await {
                    reclaimed_bytes += bytes.len() as u64;
                }
                let _ = self.hdfs.delete_file(&hdfs_file, false).await;
                deleted_orphans.push(hdfs_file);
            }
        }

        table.snapshots = retained_snapshots;
        table.last_updated_ms = now_ms;
        let next_meta_version = table.metadata_version + 1;
        table.metadata_version = next_meta_version;

        let metadata_filename = format!("{}/metadata/v{}.metadata.json", table.location, next_meta_version);
        let table_meta_bytes = serde_json::to_vec_pretty(&table)
            .map_err(|e| format!("Failed to serialize cleaned metadata: {e}"))?;

        self.hdfs
            .write_file(&metadata_filename, table_meta_bytes, true)
            .await
            .map_err(|e| format!("WebHDFS failed writing v{next_meta_version}.metadata.json: {e}"))?;

        Ok(CleanupReport {
            table_name: table_name.to_string(),
            expired_snapshots_count: expired_ids.len(),
            expired_snapshot_ids: expired_ids,
            deleted_manifest_files: deleted_manifests,
            deleted_orphan_parquet_files: deleted_orphans,
            reclaimed_bytes,
            new_metadata_version: next_meta_version,
        })
    }

    pub async fn compact_table_partitions(
        &self,
        table_name: &str,
        _target_max_file_size_bytes: u64,
        small_file_threshold_bytes: u64,
    ) -> Result<CompactionReport, String> {
        let mut tables = self.tables.write().await;
        let mut manifests = self.manifests.write().await;

        let table = tables
            .get_mut(table_name)
            .ok_or_else(|| format!("Table '{table_name}' not found"))?;

        let current_snap_id = table
            .current_snapshot_id
            .ok_or_else(|| "Table has no active snapshot to compact".to_string())?;

        let manifest_list_path = table
            .snapshots
            .iter()
            .find(|s| s.snapshot_id == current_snap_id)
            .map(|s| s.manifest_list.clone())
            .ok_or_else(|| "Active manifest list not found".to_string())?;

        let current_files = manifests
            .get(&manifest_list_path)
            .cloned()
            .unwrap_or_default();

        if current_files.len() < 2 {
            return Err("Table does not contain enough small files to require compaction".to_string());
        }

        let mut small_files = Vec::new();
        let mut retained_files = Vec::new();
        let mut original_bytes: u64 = 0;
        let mut partition_dt = "2026-09-12".to_string();

        for file in current_files {
            if (file.file_size_in_bytes as u64) < small_file_threshold_bytes {
                original_bytes += file.file_size_in_bytes as u64;
                if let Some(dt) = file.partition_values.get("dt") {
                    partition_dt = dt.clone();
                }
                small_files.push(file);
            } else {
                retained_files.push(file);
            }
        }

        if small_files.len() < 2 {
            return Err("Fewer than 2 small files qualify under the threshold".to_string());
        }

        let mut accumulated_batches = Vec::new();
        let mut schema_opt = None;

        for small_file in &small_files {
            let batches = self
                .hdfs
                .read_parquet(&small_file.file_path)
                .await
                .map_err(|e| format!("Failed reading Parquet during compaction: {e}"))?;

            for batch in batches {
                if schema_opt.is_none() {
                    schema_opt = Some(batch.schema());
                }
                accumulated_batches.push(batch);
            }
        }

        let schema = schema_opt.unwrap_or_else(|| {
            crate::compute::ArrowDataPayload::build_arrow_batch().unwrap().schema()
        });

        let unified_batch = if accumulated_batches.is_empty() {
            crate::compute::ArrowDataPayload::build_arrow_batch().unwrap()
        } else {
            arrow::compute::concat_batches(&schema, &accumulated_batches)
                .map_err(|e| format!("Failed to concatenate Arrow batches: {e}"))?
        };

        let compacted_file_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let compacted_file_path = format!(
            "{}/data/compacted-part-{}-{}.parquet",
            table.location, partition_dt, compacted_file_id
        );

        let compacted_bytes = self
            .hdfs
            .write_parquet(&compacted_file_path, &unified_batch, true)
            .await
            .map_err(|e| format!("Failed writing compacted Parquet file: {e}"))? as u64;

        let compacted_entry = ManifestFileEntry {
            file_path: compacted_file_path.clone(),
            file_format: "PARQUET".to_string(),
            record_count: unified_batch.num_rows() as i64,
            file_size_in_bytes: compacted_bytes as i64,
            partition_values: [("dt".to_string(), partition_dt.clone())].into(),
        };

        retained_files.push(compacted_entry);

        for old_file in &small_files {
            let _ = self.hdfs.delete_file(&old_file.file_path, false).await;
        }

        let new_snapshot_id = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let now_ms = chrono::Utc::now().timestamp_millis();
        let new_manifest_path = format!("{}/metadata/snap-{}.avro", table.location, new_snapshot_id);

        let manifest_bytes = serde_json::to_vec_pretty(&retained_files)
            .map_err(|e| format!("Serialization error: {e}"))?;

        self.hdfs
            .write_file(&new_manifest_path, manifest_bytes, true)
            .await
            .map_err(|e| format!("WebHDFS manifest write error: {e}"))?;

        let mut summary = HashMap::new();
        summary.insert("operation".to_string(), "replace".to_string());
        summary.insert("replace-mode".to_string(), "compaction".to_string());
        summary.insert("compacted-files-count".to_string(), small_files.len().to_string());
        summary.insert("reclaimed-file-descriptors".to_string(), (small_files.len() - 1).to_string());

        let snapshot = Snapshot {
            snapshot_id: new_snapshot_id,
            parent_snapshot_id: Some(current_snap_id),
            timestamp_ms: now_ms,
            manifest_list: new_manifest_path.clone(),
            summary,
        };

        table.snapshots.push(snapshot);
        table.current_snapshot_id = Some(new_snapshot_id);
        table.last_updated_ms = now_ms;
        let next_meta_version = table.metadata_version + 1;
        table.metadata_version = next_meta_version;

        let metadata_filename = format!("{}/metadata/v{}.metadata.json", table.location, next_meta_version);
        let meta_bytes = serde_json::to_vec_pretty(&table)
            .map_err(|e| format!("Table metadata serialization error: {e}"))?;

        self.hdfs
            .write_file(&metadata_filename, meta_bytes, true)
            .await
            .map_err(|e| format!("WebHDFS metadata write error: {e}"))?;

        manifests.insert(new_manifest_path, retained_files);

        Ok(CompactionReport {
            table_name: table_name.to_string(),
            compacted_partitions: vec![format!("dt={partition_dt}")],
            files_merged_count: small_files.len(),
            original_bytes,
            compacted_bytes,
            new_file_path: compacted_file_path,
            new_snapshot_id,
        })
    }
}
