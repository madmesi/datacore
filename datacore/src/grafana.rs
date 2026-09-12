use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

const MAX_HISTORY_POINTS: usize = 720;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricDataPoint(pub f64, pub i64);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrafanaTargetResponse {
    pub target: String,
    pub datapoints: Vec<MetricDataPoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrafanaSearchRequest {
    pub target: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrafanaQueryTarget {
    pub target: String,
    pub r#type: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrafanaTimeRange {
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrafanaQueryRequest {
    pub range: Option<GrafanaTimeRange>,
    pub interval_ms: Option<u64>,
    pub targets: Vec<GrafanaQueryTarget>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrafanaAnnotationRequest {
    pub range: Option<GrafanaTimeRange>,
    pub annotation: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrafanaAnnotation {
    pub time: i64,
    pub title: String,
    pub text: String,
    pub tags: Vec<String>,
}

#[derive(Clone)]
pub struct GrafanaTsdbEngine {
    series: Arc<RwLock<HashMap<String, VecDeque<MetricDataPoint>>>>,
    annotations: Arc<RwLock<Vec<GrafanaAnnotation>>>,
}

impl GrafanaTsdbEngine {
    pub fn new() -> Self {
        let mut initial_series = HashMap::new();
        let now = chrono::Utc::now().timestamp_millis();

        let metric_keys = vec![
            "query_latency_ms",
            "query_throughput_qps",
            "iceberg_storage_bytes",
            "hdfs_storage_bytes",
            "active_spark_executors",
            "tgt_remaining_seconds",
        ];

        for key in &metric_keys {
            let mut points = VecDeque::with_capacity(MAX_HISTORY_POINTS);
            for i in (0..360).rev() {
                let ts = now - (i * 5000);
                let val = match *key {
                    "query_latency_ms" => 1.8 + ((i as f64 * 0.1).sin() * 0.7),
                    "query_throughput_qps" => 120.0 + ((i as f64 * 0.05).cos() * 45.0),
                    "iceberg_storage_bytes" => 973934.0 + (i as f64 * 1200.0),
                    "hdfs_storage_bytes" => 973934.0,
                    "active_spark_executors" => 4.0,
                    "tgt_remaining_seconds" => 36000.0 - (i as f64 * 5.0),
                    _ => 0.0,
                };
                points.push_back(MetricDataPoint(val, ts));
            }
            initial_series.insert(key.to_string(), points);
        }

        let mut initial_annotations = Vec::new();
        initial_annotations.push(GrafanaAnnotation {
            time: now - 600000,
            title: "TGT Acquired".to_string(),
            text: "Kerberos TGT refreshed for principal spark/analytics.cluster.local".to_string(),
            tags: vec!["kerberos".to_string(), "security".to_string()],
        });

        Self {
            series: Arc::new(RwLock::new(initial_series)),
            annotations: Arc::new(RwLock::new(initial_annotations)),
        }
    }

    pub async fn record(&self, key: &str, value: f64) {
        let mut series = self.series.write().await;
        let points = series.entry(key.to_string()).or_insert_with(VecDeque::new);

        if points.len() >= MAX_HISTORY_POINTS {
            points.pop_front();
        }
        points.push_back(MetricDataPoint(value, chrono::Utc::now().timestamp_millis()));
    }

    pub async fn add_annotation(&self, title: &str, text: &str, tags: Vec<&str>) {
        let mut anns = self.annotations.write().await;
        anns.push(GrafanaAnnotation {
            time: chrono::Utc::now().timestamp_millis(),
            title: title.to_string(),
            text: text.to_string(),
            tags: tags.into_iter().map(String::from).collect(),
        });
    }

    pub async fn list_available_metrics(&self) -> Vec<String> {
        let series = self.series.read().await;
        series.keys().cloned().collect()
    }

    pub async fn query_series(&self, targets: Vec<GrafanaQueryTarget>) -> Vec<GrafanaTargetResponse> {
        let series = self.series.read().await;
        let mut response = Vec::new();

        for target in targets {
            let points = series
                .get(&target.target)
                .map(|p| p.iter().cloned().collect())
                .unwrap_or_default();

            response.push(GrafanaTargetResponse {
                target: target.target,
                datapoints: points,
            });
        }

        response
    }

    pub async fn get_annotations(&self) -> Vec<GrafanaAnnotation> {
        let anns = self.annotations.read().await;
        anns.clone()
    }
}
