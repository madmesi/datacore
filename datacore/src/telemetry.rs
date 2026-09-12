use prometheus::{
    Encoder, Gauge, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};

#[derive(Clone)]
pub struct MetricsCollector {
    registry: Registry,
    pub queries_total: IntCounterVec,
    pub query_duration_seconds: Histogram,
    pub query_rows_total: IntCounter,
    pub iceberg_snapshots: IntGauge,
    pub iceberg_data_files: IntGauge,
    pub iceberg_purged_orphans: IntCounter,
    pub kerberos_tgt_expiry: Gauge,
    pub ldap_auth_attempts: IntCounterVec,
    pub hdfs_storage_bytes: IntGauge,
    pub hdfs_io_operations: IntCounterVec,
}

impl MetricsCollector {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let registry = Registry::new();

        let queries_total = IntCounterVec::new(
            Opts::new("datacore_queries_total", "Total number of SQL queries executed"),
            &["status"],
        )?;
        let duration_opts = HistogramOpts::new(
            "datacore_query_duration_seconds",
            "Histogram of SQL query execution duration in seconds",
        )
        .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]);
        let query_duration_seconds = Histogram::with_opts(duration_opts)?;
        let query_rows_total = IntCounter::new(
            "datacore_query_rows_total",
            "Total number of tabular rows materialized by query engine",
        )?;

        let iceberg_snapshots = IntGauge::new(
            "datacore_iceberg_snapshots_total",
            "Current number of active snapshots retained in Iceberg catalog",
        )?;
        let iceberg_data_files = IntGauge::new(
            "datacore_iceberg_data_files_total",
            "Total number of tracked Parquet data files across active manifests",
        )?;
        let iceberg_purged_orphans = IntCounter::new(
            "datacore_iceberg_purged_orphan_files_total",
            "Total number of unreferenced orphan files purged by garbage collector",
        )?;

        let kerberos_tgt_expiry = Gauge::new(
            "datacore_kerberos_tgt_expiry_timestamp_seconds",
            "Epoch timestamp (seconds) when active Kerberos TGT expires",
        )?;
        let ldap_auth_attempts = IntCounterVec::new(
            Opts::new("datacore_ldap_auth_attempts_total", "Total user LDAP authentication attempts"),
            &["status"],
        )?;

        let hdfs_storage_bytes = IntGauge::new(
            "datacore_hdfs_storage_bytes_total",
            "Current total bytes allocated in cluster WebHDFS storage",
        )?;
        let hdfs_io_operations = IntCounterVec::new(
            Opts::new("datacore_hdfs_io_operations_total", "Total WebHDFS read and write operations"),
            &["operation"],
        )?;

        registry.register(Box::new(queries_total.clone()))?;
        registry.register(Box::new(query_duration_seconds.clone()))?;
        registry.register(Box::new(query_rows_total.clone()))?;
        registry.register(Box::new(iceberg_snapshots.clone()))?;
        registry.register(Box::new(iceberg_data_files.clone()))?;
        registry.register(Box::new(iceberg_purged_orphans.clone()))?;
        registry.register(Box::new(kerberos_tgt_expiry.clone()))?;
        registry.register(Box::new(ldap_auth_attempts.clone()))?;
        registry.register(Box::new(hdfs_storage_bytes.clone()))?;
        registry.register(Box::new(hdfs_io_operations.clone()))?;

        iceberg_snapshots.set(1);
        iceberg_data_files.set(2);
        kerberos_tgt_expiry.set((chrono::Utc::now().timestamp() + 36000) as f64);
        hdfs_storage_bytes.set(973934);

        Ok(Self {
            registry,
            queries_total,
            query_duration_seconds,
            query_rows_total,
            iceberg_snapshots,
            iceberg_data_files,
            iceberg_purged_orphans,
            kerberos_tgt_expiry,
            ldap_auth_attempts,
            hdfs_storage_bytes,
            hdfs_io_operations,
        })
    }

    pub fn gather_text(&self) -> String {
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap_or_default()
    }
}
