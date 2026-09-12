use arrow::array::{Array, Float64Array, Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::iceberg::IcebergCatalog;
use crate::telemetry::MetricsCollector;

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub execution_time_ms: u128,
    pub row_count: usize,
}

pub struct SqlEngine {
    ctx: Mutex<SessionContext>,
    metrics: Arc<MetricsCollector>,
}

impl SqlEngine {
    pub async fn new(
        _iceberg_catalog: Arc<IcebergCatalog>,
        metrics: Arc<MetricsCollector>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let ctx = SessionContext::new();

        let schema = Arc::new(Schema::new(vec![
            Field::new("event_id", DataType::Int64, false),
            Field::new(
                "timestamp",
                DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
                false,
            ),
            Field::new("service_name", DataType::Utf8, false),
            Field::new("cpu_usage", DataType::Float64, false),
        ]));

        let event_ids = Arc::new(Int64Array::from(vec![
            1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008,
        ]));
        let timestamps = Arc::new(arrow::array::TimestampMillisecondArray::from(vec![
            1710000000000, 1710000010000, 1710000020000, 1710000030000,
            1710000040000, 1710000050000, 1710000060000, 1710000070000,
        ]));
        let services = Arc::new(StringArray::from(vec![
            "spark-driver", "hdfs-datanode", "iceberg-catalog", "vault-agent",
            "spark-executor-1", "spark-executor-2", "freeipa-kdc", "spark-driver",
        ]));
        let cpus = Arc::new(Float64Array::from(vec![
            74.5, 12.2, 5.4, 2.1, 88.9, 93.4, 1.8, 62.0,
        ]));

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![event_ids, timestamps, services, cpus],
        )?;

        let provider = MemTable::try_new(schema, vec![vec![batch]])?;
        ctx.register_table("cluster_events", Arc::new(provider))?;

        Ok(Self {
            ctx: Mutex::new(ctx),
            metrics,
        })
    }

    pub async fn execute_query(&self, sql: &str) -> Result<QueryResult, String> {
        let start = std::time::Instant::now();
        let ctx = self.ctx.lock().await;

        let df = match ctx.sql(sql).await {
            Ok(df) => df,
            Err(e) => {
                self.metrics.queries_total.with_label_values(&["error"]).inc();
                return Err(format!("SQL compilation error: {e}"));
            }
        };

        let batches = match df.collect().await {
            Ok(b) => b,
            Err(e) => {
                self.metrics.queries_total.with_label_values(&["error"]).inc();
                return Err(format!("Execution error: {e}"));
            }
        };

        let elapsed_secs = start.elapsed().as_secs_f64();
        let elapsed_ms = (elapsed_secs * 1000.0) as u128;

        self.metrics.queries_total.with_label_values(&["success"]).inc();
        self.metrics.query_duration_seconds.observe(elapsed_secs);

        if batches.is_empty() {
            return Ok(QueryResult {
                columns: vec![],
                rows: vec![],
                execution_time_ms: elapsed_ms,
                row_count: 0,
            });
        }

        let schema = batches[0].schema();
        let columns: Vec<String> = schema.fields().iter().map(|f| f.name().clone()).collect();
        let mut rows = Vec::new();

        for batch in &batches {
            for row_idx in 0..batch.num_rows() {
                let mut row_values = Vec::new();
                for col_idx in 0..batch.num_columns() {
                    let col = batch.column(col_idx);
                    let val = Self::arrow_cell_to_json(col, row_idx);
                    row_values.push(val);
                }
                rows.push(row_values);
            }
        }

        let row_count = rows.len();
        self.metrics.query_rows_total.inc_by(row_count as u64);

        Ok(QueryResult {
            columns,
            rows,
            execution_time_ms: elapsed_ms,
            row_count,
        })
    }

    fn arrow_cell_to_json(col: &Arc<dyn Array>, idx: usize) -> serde_json::Value {
        if col.is_null(idx) {
            return serde_json::Value::Null;
        }

        match col.data_type() {
            DataType::Int64 => {
                let arr = col.as_any().downcast_ref::<Int64Array>().unwrap();
                serde_json::json!(arr.value(idx))
            }
            DataType::Float64 => {
                let arr = col.as_any().downcast_ref::<Float64Array>().unwrap();
                serde_json::json!(arr.value(idx))
            }
            DataType::Utf8 => {
                let arr = col.as_any().downcast_ref::<StringArray>().unwrap();
                serde_json::json!(arr.value(idx))
            }
            DataType::Timestamp(_, _) => {
                let arr = col
                    .as_any()
                    .downcast_ref::<arrow::array::TimestampMillisecondArray>()
                    .unwrap();
                serde_json::json!(arr.value(idx))
            }
            _ => serde_json::json!(format!("{:?}", col)),
        }
    }
}
