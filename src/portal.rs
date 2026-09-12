use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::compute::ArrowDataPayload;
use crate::grafana::{
    GrafanaAnnotation, GrafanaAnnotationRequest, GrafanaQueryRequest, GrafanaSearchRequest,
    GrafanaTargetResponse, GrafanaTsdbEngine,
};
use crate::hdfs::{FileStatus, WebHdfsClient};
use crate::iceberg::{IcebergCatalog, ManifestFileEntry, TableMetadata};
use crate::kerberos::{CachedTicket, KeytabKeyEntry};
use crate::ldap::LdapUserRecord;
use crate::security::SecurityKernel;
use crate::sql_engine::SqlEngine;
use crate::telemetry::MetricsCollector;
use crate::compute::SparkSubmitTask;
use crate::workflow::DagEngine;

#[derive(Serialize)]
struct SystemStatus {
    principal: String,
    vault_status: String,
    active_engine: String,
    arrow_version: String,
    iceberg_catalog_status: String,
    ticket_cache_status: String,
    ldap_directory_status: String,
    sql_engine_status: String,
    hdfs_client_status: String,
    prometheus_endpoint: String,
    grafana_json_endpoint: String,
}

#[derive(Deserialize)]
pub struct SqlQueryRequest {
    pub query: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct TriggerJobRequest {
    pub task_name: String,
    pub spark_app: String,
}

#[derive(Deserialize)]
pub struct TableQuery {
    pub name: String,
}

#[derive(Deserialize)]
pub struct FileQuery {
    pub path: String,
}

#[derive(Deserialize)]
pub struct WriteParquetRequest {
    pub path: String,
    pub do_as_user: Option<String>,
}

#[derive(Deserialize)]
pub struct IcebergCommitRequest {
    pub table_name: String,
    pub partition_date: String,
}

#[derive(Deserialize)]
pub struct CleanupRequest {
    pub table_name: String,
    pub retain_last_n: usize,
    pub max_age_seconds: i64,
}

#[derive(Deserialize)]
pub struct CompactionRequest {
    pub table_name: String,
    pub target_size_mb: Option<u64>,
    pub threshold_mb: Option<u64>,
}

#[derive(Deserialize)]
pub struct ApplyPolicyRequest {
    pub yaml: String,
}

#[derive(Deserialize)]
pub struct GenerateDbCredRequest {
    pub role: String,
    pub ttl_seconds: Option<i64>,
}

#[derive(Deserialize)]
pub struct RevokeDbCredRequest {
    pub lease_id: String,
}

#[derive(Deserialize)]
pub struct SparkBootstrapRequest {
    pub app_name: String,
    pub master: String,
    pub executor_count: u32,
    pub memory_mb: u32,
    pub do_as_user: Option<String>,
}

#[derive(Deserialize)]
pub struct TerminateAppRequest {
    pub app_id: String,
}

#[derive(Deserialize)]
pub struct RollKeyRequest {
    pub key_name: String,
}

#[derive(Deserialize)]
pub struct ReencryptZoneRequest {
    pub zone_path: String,
}

#[derive(Serialize)]
pub struct TableDetailResponse {
    pub metadata: TableMetadata,
    pub files: Vec<ManifestFileEntry>,
}

#[derive(Serialize)]
struct ArrowRow {
    metric_id: i64,
    cluster_node: String,
}

pub struct PortalState {
    pub security: Arc<SecurityKernel>,
    pub dag: Mutex<DagEngine>,
    pub iceberg: Arc<IcebergCatalog>,
    pub sql_engine: Arc<SqlEngine>,
    pub hdfs: Arc<WebHdfsClient>,
    pub telemetry: Arc<MetricsCollector>,
    pub grafana_tsdb: Arc<GrafanaTsdbEngine>,
    pub py4j: Arc<crate::py4j_bridge::Py4jGatewayServer>,
}

pub async fn launch_portal(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let sec = Arc::new(SecurityKernel::new());
    let dag = DagEngine::new();
    let telemetry = Arc::new(MetricsCollector::new()?);
    let grafana_tsdb = Arc::new(GrafanaTsdbEngine::new());
    let hdfs = Arc::new(WebHdfsClient::new("http://namenode.cluster.local:9870", "spark_service"));
    let iceberg = Arc::new(IcebergCatalog::new(hdfs.clone()));
    let sql_engine = Arc::new(SqlEngine::new(iceberg.clone(), telemetry.clone()).await?);
    let py4j = Arc::new(crate::py4j_bridge::Py4jGatewayServer::new(25333));
    py4j.start_listener().await.map_err(|e| e.to_string())?;

    let tsdb_clone = grafana_tsdb.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let jitter = (rand::random::<f64>() - 0.5) * 0.4;
            tsdb_clone.record("query_latency_ms", (1.5 + jitter).max(0.2)).await;
            tsdb_clone.record("active_spark_executors", 4.0).await;
        }
    });

    let vault_db_clone = sec.vault_db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let _ = vault_db_clone.purge_expired_leases().await;
        }
    });

    let state = Arc::new(PortalState {
        security: sec,
        dag: Mutex::new(dag),
        iceberg,
        sql_engine,
        hdfs,
        telemetry,
        grafana_tsdb,
        py4j,
    });

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/metrics", get(metrics_handler))
        .route("/api/status", get(status_handler))
        .route("/api/arrow/sample", get(arrow_sample_handler))
        .route("/api/dag/trigger", post(trigger_dag_handler))
        .route("/api/iceberg/tables", get(list_tables_handler))
        .route("/api/iceberg/table", get(get_table_handler))
        .route("/api/iceberg/commit", post(commit_iceberg_snapshot_handler))
        .route("/api/iceberg/cleanup", post(iceberg_cleanup_handler))
        .route("/api/iceberg/compact", post(iceberg_compaction_handler))
        .route("/api/kerberos/tickets", get(list_tickets_handler))
        .route("/api/kerberos/keytab", get(inspect_keytab_handler))
        .route("/api/kerberos/kinit", post(renew_tgt_handler))
        .route("/api/ldap/login", post(ldap_login_handler))
        .route("/api/ldap/users", get(ldap_users_handler))
        .route("/api/policy/list", get(list_policies_handler))
        .route("/api/policy/apply", post(apply_policy_handler))
        .route("/api/policy/validate-spark", post(validate_spark_job_handler))
        .route("/api/policy/validate-schema", post(validate_schema_handler))
        .route("/api/vault/db/generate", post(generate_db_creds_handler))
        .route("/api/vault/db/revoke", post(revoke_db_creds_handler))
        .route("/api/vault/db/leases", get(list_db_leases_handler))
        .route("/api/vault/db/roles", get(list_pg_roles_handler))
        .route("/api/spark/bootstrap", post(bootstrap_spark_handler))
        .route("/api/spark/apps", get(list_spark_apps_handler))
        .route("/api/spark/terminate", post(terminate_spark_app_handler))
        .route("/api/kms/zones", get(list_kms_zones_handler))
        .route("/api/kms/keys", get(list_kms_keys_handler))
        .route("/api/kms/inspect-edek", get(inspect_file_edek_handler))
        .route("/api/kms/roll-key", post(roll_kms_key_handler))
        .route("/api/kms/reencrypt-zone", post(reencrypt_zone_handler))
        .route("/api/sql/query", post(execute_sql_handler))
        .route("/api/hdfs/files", get(list_hdfs_files_handler))
        .route("/api/hdfs/write-parquet", post(write_parquet_hdfs_handler))
        .route("/api/hdfs/read-file", get(read_hdfs_file_handler))
        .route("/api/grafana/", get(grafana_health_handler))
        .route("/api/grafana/search", post(grafana_search_handler))
        .route("/api/grafana/query", post(grafana_query_handler))
        .route("/api/grafana/annotations", post(grafana_annotations_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    println!("============================================================");
    println!("  DataCore Unified Portal running at: http://localhost:{port}");
    println!("  Prometheus Scrape Endpoint at:     http://localhost:{port}/metrics");
    println!("  Py4J Spark Gateway Socket at:      port 25333");
    println!("============================================================");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn index_handler() -> Html<&'static str> {
    Html(PORTAL_HTML)
}

async fn metrics_handler(State(state): State<Arc<PortalState>>) -> Response {
    let body = state.telemetry.gather_text();
    Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn grafana_health_handler() -> impl IntoResponse {
    StatusCode::OK
}

async fn grafana_search_handler(
    State(state): State<Arc<PortalState>>,
    _body: Option<Json<GrafanaSearchRequest>>,
) -> Json<Vec<String>> {
    let metrics = state.grafana_tsdb.list_available_metrics().await;
    Json(metrics)
}

async fn grafana_query_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<GrafanaQueryRequest>,
) -> Json<Vec<GrafanaTargetResponse>> {
    let data = state.grafana_tsdb.query_series(payload.targets).await;
    Json(data)
}

async fn grafana_annotations_handler(
    State(state): State<Arc<PortalState>>,
    _body: Option<Json<GrafanaAnnotationRequest>>,
) -> Json<Vec<GrafanaAnnotation>> {
    let anns = state.grafana_tsdb.get_annotations().await;
    Json(anns)
}

async fn status_handler(State(state): State<Arc<PortalState>>) -> Json<SystemStatus> {
    let is_valid = state.security.ticket_cache.is_tgt_valid("CORP.INTERNAL").await;

    Json(SystemStatus {
        principal: "admin@CORP.INTERNAL".to_string(),
        vault_status: "Active (In-Memory Keytab Injection)".to_string(),
        active_engine: "Native Rust Kernel + Spark/Arrow Bridge".to_string(),
        arrow_version: "Apache Arrow 51.0".to_string(),
        iceberg_catalog_status: "Embedded (Direct WebHDFS Atomic Commits)".to_string(),
        ticket_cache_status: if is_valid { "Valid (TGT Active)".to_string() } else { "Expired / Empty".to_string() },
        ldap_directory_status: "Connected (FreeIPA LDAP/S)".to_string(),
        sql_engine_status: "Embedded Apache DataFusion 38.0".to_string(),
        hdfs_client_status: "Native WebHDFS Driver (Direct DataNode 307 Redirect)".to_string(),
        prometheus_endpoint: "/metrics (Active Exporter)".to_string(),
        grafana_json_endpoint: "/api/grafana (Zero-TSDB Direct Provider)".to_string(),
    })
}

async fn commit_iceberg_snapshot_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<IcebergCommitRequest>,
) -> impl IntoResponse {
    let batch = ArrowDataPayload::build_arrow_batch().unwrap();
    let part_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let file_path = format!("/warehouse/analytics/cluster_events/data/part-{part_id}.parquet");

    state.telemetry.hdfs_io_operations.with_label_values(&["write_parquet"]).inc();

    match state.hdfs.write_parquet(&file_path, &batch, true).await {
        Ok(bytes_written) => {
            state.telemetry.hdfs_storage_bytes.add(bytes_written as i64);

            let file_entry = ManifestFileEntry {
                file_path: file_path.clone(),
                file_format: "PARQUET".to_string(),
                record_count: batch.num_rows() as i64,
                file_size_in_bytes: bytes_written as i64,
                partition_values: [("dt".to_string(), payload.partition_date)].into(),
            };

            match state
                .iceberg
                .commit_snapshot_to_hdfs(&payload.table_name, vec![file_entry], "append")
                .await
            {
                Ok(snapshot) => {
                    state.telemetry.iceberg_snapshots.inc();
                    state.telemetry.iceberg_data_files.inc();
                    state.grafana_tsdb.record("iceberg_storage_bytes", bytes_written as f64).await;
                    state.grafana_tsdb.add_annotation(
                        "Iceberg Snapshot Commit",
                        &format!("Committed snapshot {} with 1 Parquet partition", snapshot.snapshot_id),
                        vec!["iceberg", "commit"],
                    ).await;

                    (StatusCode::OK, Json(serde_json::json!({
                        "status": "success",
                        "message": format!("Committed snapshot {} to HDFS", snapshot.snapshot_id),
                        "snapshot": snapshot,
                        "parquet_file": file_path
                    }))).into_response()
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "status": "error", "message": e }))).into_response(),
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "status": "error",
            "message": format!("Failed writing Parquet data file: {e}")
        }))).into_response(),
    }
}

async fn iceberg_cleanup_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<CleanupRequest>,
) -> impl IntoResponse {
    let max_age_ms = payload.max_age_seconds * 1000;
    match state
        .iceberg
        .expire_snapshots_and_clean_orphans(&payload.table_name, payload.retain_last_n, max_age_ms)
        .await
    {
        Ok(report) => {
            state.telemetry.iceberg_snapshots.sub(report.expired_snapshots_count as i64);
            state.telemetry.iceberg_purged_orphans.inc_by(report.deleted_orphan_parquet_files.len() as u64);
            state.telemetry.hdfs_storage_bytes.sub(report.reclaimed_bytes as i64);

            state.grafana_tsdb.add_annotation(
                "Iceberg Orphan Purge",
                &format!("Reclaimed {} bytes across {} orphan files", report.reclaimed_bytes, report.deleted_orphan_parquet_files.len()),
                vec!["iceberg", "gc"],
            ).await;

            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "message": format!(
                    "Pruned {} snapshot(s), deleted {} orphan Parquet file(s), reclaimed {} bytes",
                    report.expired_snapshots_count,
                    report.deleted_orphan_parquet_files.len(),
                    report.reclaimed_bytes
                ),
                "report": report
            }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "status": "error",
            "message": e
        }))).into_response(),
    }
}

async fn iceberg_compaction_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<CompactionRequest>,
) -> impl IntoResponse {
    let target_bytes = payload.target_size_mb.unwrap_or(128) * 1024 * 1024;
    let threshold_bytes = payload.threshold_mb.unwrap_or(64) * 1024 * 1024;

    match state
        .iceberg
        .compact_table_partitions(&payload.table_name, target_bytes, threshold_bytes)
        .await
    {
        Ok(report) => {
            state
                .telemetry
                .iceberg_data_files
                .sub((report.files_merged_count - 1) as i64);

            state
                .grafana_tsdb
                .add_annotation(
                    "Iceberg Partition Compaction",
                    &format!(
                        "Merged {} small files into optimal 128MB block ({})",
                        report.files_merged_count, report.new_file_path
                    ),
                    vec!["iceberg", "compaction", "optimization"],
                )
                .await;

            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "message": format!(
                    "Consolidated {} fragmented files into 1 optimal block at {}",
                    report.files_merged_count, report.new_file_path
                ),
                "report": report
            }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "status": "error",
            "message": e
        }))).into_response(),
    }
}

async fn list_hdfs_files_handler(State(state): State<Arc<PortalState>>) -> Json<Vec<FileStatus>> {
    let files = state.hdfs.list_status().await;
    Json(files)
}

async fn write_parquet_hdfs_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<WriteParquetRequest>,
) -> impl IntoResponse {
    let batch = ArrowDataPayload::build_arrow_batch().unwrap();
    state.telemetry.hdfs_io_operations.with_label_values(&["write_parquet_adhoc"]).inc();
    let do_as_ref = payload.do_as_user.as_deref();

    match state.hdfs.write_parquet_as(&payload.path, &batch, true, do_as_ref).await {
        Ok(bytes_written) => {
            state.telemetry.hdfs_storage_bytes.add(bytes_written as i64);
            let owner_name = payload.do_as_user.unwrap_or_else(|| "spark_service".to_string());
            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "message": format!("Wrote {} bytes of Parquet data to HDFS at {} with owner '{}'", bytes_written, payload.path, owner_name)
            }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "status": "error",
            "message": e.to_string()
        }))).into_response(),
    }
}

async fn read_hdfs_file_handler(
    State(state): State<Arc<PortalState>>,
    Query(query): Query<FileQuery>,
) -> impl IntoResponse {
    state.telemetry.hdfs_io_operations.with_label_values(&["read_file"]).inc();

    match state.hdfs.read_file(&query.path).await {
        Ok(bytes) => {
            if query.path.ends_with(".parquet") {
                match state.hdfs.read_parquet(&query.path).await {
                    Ok(batches) => {
                        let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
                        (StatusCode::OK, Json(serde_json::json!({
                            "status": "success",
                            "type": "parquet",
                            "summary": format!("Decoded {} Parquet record batch(es) with {} total rows", batches.len(), total_rows)
                        }))).into_response()
                    }
                    Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "status": "error", "message": e.to_string() }))).into_response(),
                }
            } else {
                let content = String::from_utf8_lossy(&bytes).to_string();
                (StatusCode::OK, Json(serde_json::json!({
                    "status": "success",
                    "type": "text/metadata",
                    "content": content
                }))).into_response()
            }
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "error", "message": e.to_string() }))).into_response(),
    }
}

async fn execute_sql_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<SqlQueryRequest>,
) -> impl IntoResponse {
    match state.sql_engine.execute_query(&payload.query).await {
        Ok(res) => {
            state.grafana_tsdb.record("query_latency_ms", res.execution_time_ms as f64).await;
            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "data": res
            }))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "status": "error",
            "message": e
        }))).into_response(),
    }
}

async fn ldap_login_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    match state.security.authenticate(&payload.username, &payload.password).await {
        Ok(identity) => {
            state.telemetry.ldap_auth_attempts.with_label_values(&["success"]).inc();
            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "message": format!("Authenticated DN for {}", identity.username),
                "identity": {
                    "username": identity.username,
                    "principal": identity.kerberos_principal,
                    "email": identity.email,
                    "groups": identity.groups,
                    "token": identity.session_token
                }
            }))).into_response()
        }
        Err(e) => {
            state.telemetry.ldap_auth_attempts.with_label_values(&["failure"]).inc();
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
                "status": "error",
                "message": e.to_string()
            }))).into_response()
        }
    }
}

async fn ldap_users_handler(State(state): State<Arc<PortalState>>) -> Json<Vec<LdapUserRecord>> {
    let users = state.security.ldap.search_users("").await;
    Json(users)
}

async fn list_policies_handler(State(state): State<Arc<PortalState>>) -> Json<Vec<String>> {
    let policies = state.security.admission.list_policies_yaml().await;
    Json(policies)
}

async fn apply_policy_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<ApplyPolicyRequest>,
) -> impl IntoResponse {
    match state.security.admission.apply_policy_yaml(&payload.yaml).await {
        Ok(pol) => (StatusCode::OK, Json(serde_json::json!({
            "status": "success",
            "message": format!("Successfully applied ClusterPolicy '{}'", pol.metadata.name),
            "policy": pol
        }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "status": "error",
            "message": e
        }))).into_response(),
    }
}

async fn validate_spark_job_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<crate::policy::SparkJobAdmissionRequest>,
) -> Json<crate::policy::AdmissionDecision> {
    let decision = state.security.admission.validate_spark_job(&payload).await;
    Json(decision)
}

async fn validate_schema_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<crate::policy::SchemaAdmissionRequest>,
) -> Json<crate::policy::AdmissionDecision> {
    let decision = state.security.admission.validate_iceberg_schema(&payload).await;
    Json(decision)
}

async fn generate_db_creds_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<GenerateDbCredRequest>,
) -> impl IntoResponse {
    match state.security.vault_db.generate_credentials(&payload.role, payload.ttl_seconds).await {
        Ok(cred) => {
            state.grafana_tsdb.add_annotation(
                "Dynamic DB Credential Issued",
                &format!("Issued ephemeral PostgreSQL user '{}' (TTL: {}s)", cred.username, cred.ttl_secs),
                vec!["vault", "postgres", "security"],
            ).await;

            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "credential": cred
            }))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "status": "error",
            "message": e
        }))).into_response(),
    }
}

async fn revoke_db_creds_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<RevokeDbCredRequest>,
) -> impl IntoResponse {
    match state.security.vault_db.revoke_lease(&payload.lease_id).await {
        Ok(msg) => {
            state.grafana_tsdb.add_annotation(
                "Dynamic DB Credential Revoked",
                &msg,
                vec!["vault", "postgres", "revoke"],
            ).await;

            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "message": msg
            }))).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "status": "error",
            "message": e
        }))).into_response(),
    }
}

async fn list_db_leases_handler(State(state): State<Arc<PortalState>>) -> Json<Vec<crate::vault_db::DynamicDbCredential>> {
    let leases = state.security.vault_db.list_active_leases().await;
    Json(leases)
}

async fn list_pg_roles_handler(State(state): State<Arc<PortalState>>) -> Json<Vec<crate::vault_db::SimulatedPgUser>> {
    let roles = state.security.vault_db.list_pg_roles().await;
    Json(roles)
}

async fn bootstrap_spark_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<SparkBootstrapRequest>,
) -> impl IntoResponse {
    let do_as = payload.do_as_user.unwrap_or_else(|| "admin".to_string());

    let admission_req = crate::policy::SparkJobAdmissionRequest {
        job_name: payload.app_name.clone(),
        image: "docker.io/apache/spark:3.5.1".to_string(),
        run_as_user: 1001,
        privileged: false,
        cpu_cores: payload.executor_count,
        memory_mb: payload.memory_mb as u64,
    };
    let decision = state.security.admission.validate_spark_job(&admission_req).await;
    if !decision.allowed {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "status": "error",
            "message": format!("Rejected by Admission Policy: {:?}", decision.violations)
        }))).into_response();
    }

    let krb_principal = "spark/analytics.cluster.local@CORP.INTERNAL";

    match state
        .py4j
        .bootstrap_spark_session(
            &payload.app_name,
            &payload.master,
            payload.executor_count,
            payload.memory_mb,
            krb_principal,
            &do_as,
        )
        .await
    {
        Ok(app) => {
            state.grafana_tsdb.record("active_spark_executors", app.executor_count as f64).await;
            state
                .grafana_tsdb
                .add_annotation(
                    "Spark Session Bootstrapped (doAs)",
                    &format!("Bootstrapped SparkContext for '{}' with doAs='{}' (App ID: {})", app.app_name, app.impersonated_do_as_user, app.app_id),
                    vec!["spark", "py4j", "doAs", "impersonation"],
                )
                .await;

            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "message": format!("SparkContext initialized on Py4J port 25333 with doAs='{}'", app.impersonated_do_as_user),
                "app": app
            }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "status": "error", "message": e }))).into_response(),
    }
}

async fn list_spark_apps_handler(
    State(state): State<Arc<PortalState>>,
) -> Json<Vec<crate::py4j_bridge::ActiveSparkApp>> {
    let apps = state.py4j.list_apps().await;
    Json(apps)
}

async fn terminate_spark_app_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<TerminateAppRequest>,
) -> impl IntoResponse {
    match state.py4j.complete_app(&payload.app_id).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({
            "status": "success",
            "message": format!("Halted SparkContext {}", payload.app_id)
        }))).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "error", "message": e }))).into_response(),
    }
}

async fn list_kms_zones_handler(State(state): State<Arc<PortalState>>) -> Json<Vec<crate::kms::EncryptionZoneConfig>> {
    let zones = state.hdfs.kms.list_zones().await;
    Json(zones)
}

async fn list_kms_keys_handler(State(state): State<Arc<PortalState>>) -> Json<Vec<crate::kms::MasterKeyEntry>> {
    let keys = state.hdfs.kms.list_all_key_versions().await;
    Json(keys)
}

async fn inspect_file_edek_handler(
    State(state): State<Arc<PortalState>>,
    Query(query): Query<FileQuery>,
) -> impl IntoResponse {
    if let Some(hdr) = state.hdfs.get_crypto_header(&query.path).await {
        Json(serde_json::json!({
            "status": "encrypted",
            "tde_enabled": true,
            "header": hdr
        }))
    } else {
        Json(serde_json::json!({
            "status": "unencrypted",
            "tde_enabled": false,
            "message": "File is stored in plaintext (not in an encryption zone)"
        }))
    }
}

async fn roll_kms_key_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<RollKeyRequest>,
) -> impl IntoResponse {
    match state.hdfs.kms.roll_new_master_key_version(&payload.key_name).await {
        Ok(new_key) => {
            state.grafana_tsdb.add_annotation(
                "KMS Master Key Rotated",
                &format!("Rotated '{}' to version '{}' for compliance", new_key.key_name, new_key.version),
                vec!["kms", "tde", "key-rotation", "compliance"],
            ).await;

            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "message": format!("Rotated key '{}' to new active version '{}'", new_key.key_name, new_key.version),
                "key": new_key
            }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "status": "error", "message": e.to_string() }))).into_response(),
    }
}

async fn reencrypt_zone_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<ReencryptZoneRequest>,
) -> impl IntoResponse {
    match state.hdfs.reencrypt_zone_edeks(&payload.zone_path).await {
        Ok(summary) => {
            state.grafana_tsdb.add_annotation(
                "Batch EDEK Re-encryption",
                &format!("Re-encrypted {} EDEKs in zone '{}' to key version '{}'", summary.reencrypted_files_count, summary.zone_path, summary.target_version),
                vec!["kms", "tde", "reencrypt", "compliance"],
            ).await;

            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "message": format!("Batch re-encrypted {} file EDEK(s) to version '{}'", summary.reencrypted_files_count, summary.target_version),
                "summary": summary
            }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "status": "error", "message": e.to_string() }))).into_response(),
    }
}

async fn list_tickets_handler(State(state): State<Arc<PortalState>>) -> Json<Vec<CachedTicket>> {
    let tickets = state.security.ticket_cache.list_tickets().await;
    Json(tickets)
}

async fn inspect_keytab_handler(State(state): State<Arc<PortalState>>) -> Json<Vec<KeytabKeyEntry>> {
    let entries = state
        .security
        .get_parsed_keytab("secret/data/spark/keytab_raw")
        .unwrap_or_default();
    Json(entries)
}

async fn renew_tgt_handler(State(state): State<Arc<PortalState>>) -> impl IntoResponse {
    match state.security.renew_tgt().await {
        Ok(tgt) => {
            state.telemetry.kerberos_tgt_expiry.set(tgt.end_time as f64);
            state.grafana_tsdb.add_annotation(
                "Kerberos TGT Renewed",
                &format!("Ticket renewed until {}", tgt.end_time),
                vec!["kerberos", "kinit"],
            ).await;
            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "message": format!("TGT acquired for {} expiring at {}", tgt.server, tgt.end_time)
            }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "status": "error",
            "message": e.to_string()
        }))).into_response(),
    }
}

async fn list_tables_handler(State(state): State<Arc<PortalState>>) -> Json<Vec<String>> {
    let tables = state.iceberg.list_tables().await;
    Json(tables)
}

async fn get_table_handler(
    State(state): State<Arc<PortalState>>,
    Query(query): Query<TableQuery>,
) -> Result<Json<TableDetailResponse>, (StatusCode, String)> {
    if let Some(metadata) = state.iceberg.get_table(&query.name).await {
        let manifest_list = metadata
            .snapshots
            .last()
            .map(|s| s.manifest_list.clone())
            .unwrap_or_default();
        let files = state.iceberg.get_manifest_files(&manifest_list).await;

        Ok(Json(TableDetailResponse { metadata, files }))
    } else {
        Err((StatusCode::NOT_FOUND, "Table not found".into()))
    }
}

async fn arrow_sample_handler() -> Json<Vec<ArrowRow>> {
    let batch = ArrowDataPayload::build_arrow_batch().unwrap();
    let id_col = batch
        .column(0)
        .as_any()
        .downcast_ref::<arrow::array::Int64Array>()
        .unwrap();
    let node_col = batch
        .column(1)
        .as_any()
        .downcast_ref::<arrow::array::StringArray>()
        .unwrap();

    let rows: Vec<ArrowRow> = (0..batch.num_rows())
        .map(|i| ArrowRow {
            metric_id: id_col.value(i),
            cluster_node: node_col.value(i).to_string(),
        })
        .collect();

    Json(rows)
}

async fn trigger_dag_handler(
    State(state): State<Arc<PortalState>>,
    Json(payload): Json<TriggerJobRequest>,
) -> impl IntoResponse {
    let keytab = state
        .security
        .fetch_vault_secret("secret/data/spark/keytab_raw")
        .unwrap();

    let mut dag = state.dag.lock().await;
    dag.register_task(
        Box::new(SparkSubmitTask {
            task_name: payload.task_name.clone(),
            app_resource: payload.spark_app,
            main_class: "org.datacore.UnifiedTask".to_string(),
            kerberos_keytab_payload: keytab,
        }),
        vec![],
    );

    match dag.run().await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({
            "status": "success",
            "message": format!("Task '{}' executed successfully", payload.task_name)
        }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "status": "error",
            "message": e
        }))).into_response(),
    }
}

const PORTAL_HTML: &str = r###"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>DataCore Control Portal</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --accent: #58a6ff;
      --iceberg: #38bdf8;
      --hdfs: #f0883e;
      --sql: #3fb950;
      --krb: #e3b341;
      --ldap: #a371f7;
      --prom: #f85149;
      --grafana: #ff7800;
      --success: #2ea043;
      --danger: #f85149;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 24px;
    }
    h1 { color: #ffffff; margin-bottom: 4px; }
    .subtitle { color: #8b949e; margin-bottom: 24px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 20px; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    h2 { font-size: 1.1rem; color: #fff; margin-top: 0; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
    .badge {
      display: inline-block;
      padding: 4px 8px;
      font-size: 12px;
      border-radius: 4px;
      background: #1f6feb22;
      color: var(--accent);
      border: 1px solid var(--accent);
    }
    .badge-iceberg { background: #0284c722; color: var(--iceberg); border: 1px solid var(--iceberg); }
    .badge-hdfs { background: #bd561122; color: var(--hdfs); border: 1px solid var(--hdfs); }
    .badge-sql { background: #23863622; color: var(--sql); border: 1px solid var(--sql); }
    .badge-prom { background: #da363322; color: var(--prom); border: 1px solid var(--prom); }
    .badge-grafana { background: #ff780022; color: var(--grafana); border: 1px solid var(--grafana); }
    .badge-krb { background: #bb800922; color: var(--krb); border: 1px solid var(--krb); }
    .badge-ldap { background: #8957e522; color: var(--ldap); border: 1px solid var(--ldap); }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
    th { color: #8b949e; }
    button {
      background: var(--success);
      color: #fff;
      border: none;
      padding: 8px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
    }
    button.btn-grafana { background: var(--grafana); color: #fff; }
    button.btn-sql { background: #238636; }
    button.btn-iceberg { background: #0284c7; }
    button.btn-hdfs { background: #d97706; }
    button.btn-prom { background: #da3633; color: #fff; }
    button.btn-krb { background: #d29922; color: #000; }
    button:hover { opacity: 0.9; }
    select, input, textarea {
      background: #0d1117;
      border: 1px solid var(--border);
      color: #fff;
      padding: 8px;
      border-radius: 4px;
      width: 96%;
      margin-bottom: 10px;
      font-family: monospace;
    }
    textarea { height: 70px; resize: vertical; }
    pre { background: #090d13; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
    svg { background: #090d13; border-radius: 6px; width: 100%; height: 160px; }
  </style>
</head>
<body>
  <h1>DataCore Unified Platform</h1>
  <div class="subtitle">Unified Execution Kernel, Native Lakehouse, WebHDFS, KMS & Py4J Gateway</div>

  <div class="grid">
    <div class="card">
      <h2>Cluster Subsystem Status</h2>
      <p><strong>Grafana JSON Datasource:</strong> <span id="grafanaStatus" class="badge badge-grafana">...</span></p>
      <p><strong>Prometheus Scrape:</strong> <a href="/metrics" target="_blank" style="color:var(--prom); text-decoration:none;"><span id="promStatus" class="badge badge-prom">...</span></a></p>
      <p><strong>Query Engine:</strong> <span id="sqlEngine" class="badge badge-sql">...</span></p>
      <p><strong>Metastore Engine:</strong> <span id="icebergCatalog" class="badge badge-iceberg">...</span></p>
      <p><strong>Storage & KMS:</strong> <span id="hdfsStatus" class="badge badge-hdfs">...</span></p>
    </div>

    <div class="card" style="grid-column: 1 / -1;">
      <h2>Native Grafana Time-Series Provider (Zero External TSDB)</h2>
      <div style="display:flex; gap:12px; align-items:center; margin-bottom:12px;">
        <label style="font-size:13px;">Target Metric:</label>
        <select id="metricSelector" onchange="fetchGrafanaChart()" style="width:240px; margin-bottom:0;">
          <option value="query_latency_ms">query_latency_ms</option>
          <option value="query_throughput_qps">query_throughput_qps</option>
          <option value="iceberg_storage_bytes">iceberg_storage_bytes</option>
          <option value="active_spark_executors">active_spark_executors</option>
        </select>
        <button class="btn-grafana" onclick="fetchGrafanaChart()">Refresh Series</button>
        <span id="chartMeta" style="color:#8b949e; font-size:12px; margin-left:auto;"></span>
      </div>
      <svg id="grafanaSvg" viewBox="0 0 800 160"></svg>
    </div>

    <div class="card" style="grid-column: 1 / -1;">
      <h2>Interactive SQL Query Console (DataFusion over Iceberg)</h2>
      <textarea id="sqlInput">SELECT service_name, COUNT(*) as events, AVG(cpu_usage) as avg_cpu FROM cluster_events GROUP BY service_name ORDER BY avg_cpu DESC;</textarea>
      <div>
        <button class="btn-sql" onclick="runSqlQuery()">Run Query</button>
        <span id="queryStats" style="margin-left: 14px; font-size: 13px; color: #8b949e;"></span>
      </div>
      <table id="sqlResultsTable">
        <thead><tr id="sqlResultsHead"></tr></thead>
        <tbody id="sqlResultsBody">
          <tr><td>Execute query above to view results.</td></tr>
        </tbody>
      </table>
    </div>

    <div class="card" style="grid-column: 1 / -1;">
      <h2>Hadoop KMS Transparent Data Encryption & Key Rotation</h2>
      <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
        <div>
          <label style="font-weight:600;">Configured Encryption Zones</label>
          <table id="kmsZonesTable">
            <thead>
              <tr><th>Zone Path</th><th>Master Key</th><th>Cipher Suite</th></tr>
            </thead>
            <tbody>
              <tr><td colspan="3">Loading zones...</td></tr>
            </tbody>
          </table>
          <div style="margin-top:12px; display:flex; gap:8px;">
            <button class="btn-prom" onclick="rollMasterKey()">Roll Master Key</button>
            <button class="btn-sql" onclick="reencryptZone()">Batch Re-encrypt EDEKs</button>
          </div>
          <pre id="kmsRotateOutput" style="height:60px; margin-top:8px;">Ready for compliance rotation.</pre>
        </div>
        <div>
          <label style="font-weight:600;">Inspect File Envelope Crypto Attributes</label>
          <div style="display:flex; gap:8px;">
            <input type="text" id="kmsInspectPath" value="/warehouse/analytics/cluster_events/data/part-00000.parquet" />
            <button class="btn-sql" onclick="inspectFileEdek()" style="white-space:nowrap;">Inspect EDEK</button>
          </div>
          <pre id="edekOutput" style="height: 120px; margin-top:8px;">Click 'Inspect EDEK' to view extended crypto attributes.</pre>
        </div>
      </div>
    </div>

    <div class="card" style="grid-column: 1 / -1;">
      <h2>Native Py4J & JNI Spark Launcher (with Hadoop doAs Impersonation)</h2>
      <div style="display:grid; grid-template-columns: 340px 1fr; gap:16px;">
        <div>
          <label>Spark Application Name</label>
          <input type="text" id="sparkAppName" value="iceberg_vectorized_etl" />
          <label>Hadoop doAs User (from LDAP)</label>
          <select id="sparkDoAsUser">
            <option value="jdoe">jdoe (Analytics Engineer / spark-users)</option>
            <option value="admin">admin (Directory Administrator / admins)</option>
          </select>
          <label>Master URL</label>
          <input type="text" id="sparkMaster" value="local[4]" />
          <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
            <div>
              <label style="font-size:11px;">Executors</label>
              <input type="number" id="sparkExecutors" value="4" min="1" max="16" />
            </div>
            <div>
              <label style="font-size:11px;">RAM (MB)</label>
              <input type="number" id="sparkRam" value="8192" min="1024" />
            </div>
          </div>
          <button class="btn-sql" onclick="bootstrapSparkSession()" style="margin-top:8px;">Bootstrap SparkContext (doAs)</button>
          <pre id="sparkBootstrapOutput" style="margin-top:10px; height:70px;">Awaiting launch...</pre>
        </div>
        <div>
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <label style="font-weight:600;">Active Sessions (Tracking Proxy & doAs Identities)</label>
            <button onclick="loadSparkApps()" style="padding:4px 8px; font-size:11px;">Refresh</button>
          </div>
          <table id="sparkAppsTable">
            <thead>
              <tr><th>App ID</th><th>Name</th><th>Impersonated (doAs)</th><th>Executors</th><th>Status</th><th>Action</th></tr>
            </thead>
            <tbody>
              <tr><td colspan="6">No active Spark applications.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="card" style="grid-column: 1 / -1;">
      <h2>Vault Dynamic PostgreSQL Credential Engine</h2>
      <div style="display:grid; grid-template-columns: 320px 1fr; gap:16px;">
        <div>
          <label>Target Vault DB Role</label>
          <select id="dbRoleSelect">
            <option value="spark-readonly">spark-readonly (analytics_warehouse)</option>
            <option value="airflow-writer">airflow-writer (analytics_warehouse)</option>
          </select>
          <label>Lease TTL (Seconds)</label>
          <input type="number" id="dbTtlInput" value="60" min="10" />
          <button class="btn-krb" onclick="generateDbCredentials()">Generate Dynamic Credentials</button>
          <pre id="dbCredsOutput" style="margin-top:10px; height:80px;">Awaiting request...</pre>
        </div>
        <div>
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <label style="font-weight:600;">Active Ephemeral Leases & Live PostgreSQL Roles</label>
            <button onclick="loadVaultDb()" style="padding:4px 8px; font-size:11px;">Refresh</button>
          </div>
          <table id="vaultLeasesTable">
            <thead>
              <tr><th>Username</th><th>Database</th><th>Expires In</th><th>Lease ID</th><th>Action</th></tr>
            </thead>
            <tbody>
              <tr><td colspan="5">No active dynamic leases in PostgreSQL.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>Iceberg Operations & Compaction</h2>
      <input type="text" id="cleanTable" value="analytics.cluster_events" />
      <div style="display:flex; gap:8px;">
        <button class="btn-iceberg" onclick="commitIcebergSnapshot()">Commit Snapshot</button>
        <button class="btn-hdfs" onclick="runCompaction()">Compact (128MB)</button>
        <button class="btn-prom" onclick="runIcebergCleanup()">Purge Orphans</button>
      </div>
      <pre id="actionOutput" style="margin-top:8px;">Ready for operations.</pre>
    </div>

    <div class="card">
      <h2>WebHDFS Storage Browser</h2>
      <table id="hdfsFilesTable">
        <thead>
          <tr><th>Path</th><th>Size (Bytes)</th><th>Owner</th></tr>
        </thead>
        <tbody>
          <tr><td colspan="3">Querying HDFS...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <script>
    async function loadStatus() {
      const res = await fetch('/api/status');
      const data = await res.json();
      document.getElementById('grafanaStatus').innerText = data.grafana_json_endpoint;
      document.getElementById('promStatus').innerText = data.prometheus_endpoint;
      document.getElementById('sqlEngine').innerText = data.sql_engine_status;
      document.getElementById('icebergCatalog').innerText = data.iceberg_catalog_status;
      document.getElementById('hdfsStatus').innerText = data.hdfs_client_status;
    }

    async function fetchGrafanaChart() {
      const metric = document.getElementById('metricSelector').value;
      const res = await fetch('/api/grafana/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets: [{ target: metric }] })
      });
      const data = await res.json();
      if (data.length === 0 || !data[0].datapoints.length) return;

      const points = data[0].datapoints;
      const svg = document.getElementById('grafanaSvg');
      const meta = document.getElementById('chartMeta');

      const values = points.map(p => p[0]);
      const min = Math.min(...values);
      const max = Math.max(...values);
      const range = (max - min) || 1.0;
      const width = 800;
      const height = 160;
      const padding = 20;

      let d = '';
      points.forEach((p, idx) => {
        const x = padding + (idx / (points.length - 1)) * (width - (padding * 2));
        const y = height - padding - ((p[0] - min) / range) * (height - (padding * 2));
        d += (idx === 0 ? `M ${x} ${y}` : ` L ${x} ${y}`);
      });

      svg.innerHTML = `
        <line x1="${padding}" y1="${height - padding}" x2="${width - padding}" y2="${height - padding}" stroke="#30363d" />
        <path d="${d}" fill="none" stroke="var(--grafana)" stroke-width="2" />
      `;

      const lastVal = points[points.length - 1][0].toFixed(2);
      meta.innerText = `Latest: ${lastVal} | Min: ${min.toFixed(2)} | Max: ${max.toFixed(2)} (${points.length} points)`;
    }

    async function runSqlQuery() {
      const query = document.getElementById('sqlInput').value;
      const stats = document.getElementById('queryStats');
      const thead = document.getElementById('sqlResultsHead');
      const tbody = document.getElementById('sqlResultsBody');

      stats.innerText = 'Executing query on DataFusion engine...';

      const res = await fetch('/api/sql/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query })
      });

      const response = await res.json();
      if (response.status === 'error') {
        stats.innerText = response.message;
        return;
      }

      const qData = response.data;
      stats.innerText = `Returned ${qData.row_count} rows in ${qData.execution_time_ms} ms (Ingested to Grafana TSDB)`;

      thead.innerHTML = '';
      qData.columns.forEach(col => { thead.innerHTML += `<th>${col}</th>`; });

      tbody.innerHTML = '';
      qData.rows.forEach(row => {
        let rowHtml = '<tr>';
        row.forEach(val => { rowHtml += `<td><code>${val !== null ? val : 'NULL'}</code></td>`; });
        rowHtml += '</tr>';
        tbody.innerHTML += rowHtml;
      });

      fetchGrafanaChart();
    }

    async function commitIcebergSnapshot() {
      const out = document.getElementById('actionOutput');
      out.innerText = 'Committing snapshot...';
      const body = {
        table_name: document.getElementById('cleanTable').value,
        partition_date: '2026-09-12'
      };
      const res = await fetch('/api/iceberg/commit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      out.innerText = JSON.stringify(data, null, 2);
      loadHdfsFiles();
      fetchGrafanaChart();
    }

    async function runCompaction() {
      const out = document.getElementById('actionOutput');
      out.innerText = 'Compacting small Parquet partitions into 128MB blocks...';
      const body = {
        table_name: document.getElementById('cleanTable').value,
        target_size_mb: 128,
        threshold_mb: 64
      };
      const res = await fetch('/api/iceberg/compact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      out.innerText = JSON.stringify(data, null, 2);
      loadHdfsFiles();
      fetchGrafanaChart();
    }

    async function runIcebergCleanup() {
      const out = document.getElementById('actionOutput');
      out.innerText = 'Purging orphan files...';
      const body = {
        table_name: document.getElementById('cleanTable').value,
        retain_last_n: 1,
        max_age_seconds: 0
      };
      const res = await fetch('/api/iceberg/cleanup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      out.innerText = JSON.stringify(data, null, 2);
      loadHdfsFiles();
      fetchGrafanaChart();
    }

    async function loadHdfsFiles() {
      const res = await fetch('/api/hdfs/files');
      const files = await res.json();
      const tbody = document.querySelector('#hdfsFilesTable tbody');
      tbody.innerHTML = '';
      files.forEach(f => {
        tbody.innerHTML += `<tr>
          <td><code>${f.path}</code></td>
          <td>${f.length.toLocaleString()}</td>
          <td><span class="badge badge-ldap">${f.owner}</span></td>
        </tr>`;
      });
    }

    async function loadKmsZones() {
      const res = await fetch('/api/kms/zones');
      const zones = await res.json();
      const tbody = document.querySelector('#kmsZonesTable tbody');
      tbody.innerHTML = '';
      zones.forEach(z => {
        tbody.innerHTML += `<tr>
          <td><code>${z.zone_path}</code></td>
          <td><span class="badge badge-krb">${z.key_name}</span></td>
          <td><span class="badge badge-sql">AES/CTR/NoPadding (256-bit)</span></td>
        </tr>`;
      });
    }

    async function inspectFileEdek() {
      const path = document.getElementById('kmsInspectPath').value;
      const out = document.getElementById('edekOutput');
      out.innerText = `Fetching crypto attributes for ${path}...`;

      const res = await fetch(`/api/kms/inspect-edek?path=${encodeURIComponent(path)}`);
      const data = await res.json();
      out.innerText = JSON.stringify(data, null, 2);
    }

    async function rollMasterKey() {
      const out = document.getElementById('kmsRotateOutput');
      out.innerText = 'Rolling 256-bit Master Key version...';
      const res = await fetch('/api/kms/roll-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key_name: 'ez-analytics-key' })
      });
      const data = await res.json();
      out.innerText = JSON.stringify(data, null, 2);
    }

    async function reencryptZone() {
      const out = document.getElementById('kmsRotateOutput');
      out.innerText = 'Re-encrypting zone EDEKs zero-copy...';
      const res = await fetch('/api/kms/reencrypt-zone', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ zone_path: '/warehouse/analytics' })
      });
      const data = await res.json();
      out.innerText = JSON.stringify(data, null, 2);
      inspectFileEdek();
    }

    async function bootstrapSparkSession() {
      const out = document.getElementById('sparkBootstrapOutput');
      out.innerText = 'Bootstrapping SparkContext via Py4J...';
      const body = {
        app_name: document.getElementById('sparkAppName').value,
        master: document.getElementById('sparkMaster').value,
        executor_count: parseInt(document.getElementById('sparkExecutors').value),
        memory_mb: parseInt(document.getElementById('sparkRam').value),
        do_as_user: document.getElementById('sparkDoAsUser').value
      };

      const res = await fetch('/api/spark/bootstrap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      out.innerText = JSON.stringify(data, null, 2);
      loadSparkApps();
      fetchGrafanaChart();
    }

    async function loadSparkApps() {
      const res = await fetch('/api/spark/apps');
      const apps = await res.json();
      const tbody = document.querySelector('#sparkAppsTable tbody');
      tbody.innerHTML = '';

      if (apps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="color:#8b949e;">No active Spark applications.</td></tr>';
        return;
      }

      apps.forEach(a => {
        const isRunning = a.status === 'RUNNING';
        const statusBadgeClass = isRunning ? 'badge-sql' : 'badge-iceberg';
        tbody.innerHTML += `<tr>
          <td><code>${a.app_id}</code></td>
          <td>${a.app_name}</td>
          <td><span class="badge badge-ldap">doAs: ${a.impersonated_do_as_user}</span></td>
          <td>${a.executor_count}x (${a.memory_per_executor_mb}MB)</td>
          <td><span class="badge ${statusBadgeClass}">${a.status}</span></td>
          <td>${isRunning ? `<button onclick="terminateSparkApp('${a.app_id}')" style="background:var(--danger); padding:4px 8px; font-size:11px;">Stop</button>` : '-'}</td>
        </tr>`;
      });
    }

    async function terminateSparkApp(appId) {
      await fetch('/api/spark/terminate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ app_id: appId })
      });
      loadSparkApps();
    }

    async function generateDbCredentials() {
      const out = document.getElementById('dbCredsOutput');
      out.innerText = 'Minting ephemeral database role and password...';
      const role = document.getElementById('dbRoleSelect').value;
      const ttl = parseInt(document.getElementById('dbTtlInput').value);

      const res = await fetch('/api/vault/db/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role, ttl_seconds: ttl })
      });
      const data = await res.json();
      out.innerText = JSON.stringify(data, null, 2);
      loadVaultDb();
    }

    async function revokeDbLease(leaseId) {
      await fetch('/api/vault/db/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ lease_id: leaseId })
      });
      loadVaultDb();
    }

    async function loadVaultDb() {
      const res = await fetch('/api/vault/db/leases');
      const leases = await res.json();
      const tbody = document.querySelector('#vaultLeasesTable tbody');
      tbody.innerHTML = '';

      if (leases.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="color:#8b949e;">No active dynamic leases in PostgreSQL.</td></tr>';
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      leases.forEach(l => {
        const remaining = Math.max(0, l.expire_time - now);
        tbody.innerHTML += `<tr>
          <td><code>${l.username}</code></td>
          <td>${l.db_name}</td>
          <td><span class="badge badge-krb">${remaining}s remaining</span></td>
          <td style="font-size:11px;"><code>${l.lease_id.split('/').pop()}</code></td>
          <td><button onclick="revokeDbLease('${l.lease_id}')" style="background:var(--danger); padding:4px 8px; font-size:11px;">Revoke</button></td>
        </tr>`;
      });
    }

    loadStatus();
    loadHdfsFiles();
    loadKmsZones();
    loadSparkApps();
    loadVaultDb();
    fetchGrafanaChart();
    setInterval(fetchGrafanaChart, 5000);
    setInterval(loadVaultDb, 3000);
  </script>
</body>
</html>
"###;
