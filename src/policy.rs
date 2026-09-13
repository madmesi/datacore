use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparkJobAdmissionRequest {
    pub job_name: String,
    pub image: String,
    pub run_as_user: u32,
    pub privileged: bool,
    pub cpu_cores: u32,
    pub memory_mb: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchemaAdmissionRequest {
    pub table_name: String,
    pub proposed_schema_json: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionDecision {
    pub allowed: bool,
    pub violations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterPolicy {
    // This tells the parser to look for "apiVersion" in the YAML, 
    // but map it to "api_version" in Rust.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: PolicyMetadata,
    #[serde(default)]
    pub spec: serde_yaml::Value,
}

pub struct AdmissionController {
    policies: Arc<RwLock<Vec<ClusterPolicy>>>,
}

impl AdmissionController {
    pub fn new() -> Self {
        let default_yaml = r#"
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-spark-privileged
spec:
  validationFailureAction: enforce
  rules:
    - name: prevent-root-and-privileged
      match:
        resources:
          kinds:
            - SparkApplication
"#;
        // This will now parse successfully without panicking.
        let default_policy: ClusterPolicy = serde_yaml::from_str(default_yaml)
            .expect("Failed to parse default policy");

        Self {
            policies: Arc::new(RwLock::new(vec![default_policy])),
        }
    }

    pub async fn list_policies_yaml(&self) -> Vec<String> {
        let policies = self.policies.read().await;
        policies
            .iter()
            .map(|p| serde_yaml::to_string(p).unwrap())
            .collect()
    }

    pub async fn apply_policy_yaml(&self, yaml: &str) -> Result<ClusterPolicy, String> {
        let policy: ClusterPolicy = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
        let mut policies = self.policies.write().await;
        policies.push(policy.clone());
        Ok(policy)
    }

    pub async fn validate_spark_job(&self, req: &SparkJobAdmissionRequest) -> AdmissionDecision {
        let mut violations = Vec::new();

        if req.privileged {
            violations.push("Spark containers cannot run in privileged mode.".to_string());
        }
        
        if req.run_as_user == 0 {
            violations.push("Spark containers cannot run as root (user 0).".to_string());
        }

        if req.cpu_cores > 32 {
            violations.push(format!(
                "Requested CPU cores ({}) exceeds policy limit of 32.",
                req.cpu_cores
            ));
        }

        AdmissionDecision {
            allowed: violations.is_empty(),
            violations,
        }
    }

    pub async fn validate_iceberg_schema(&self, _req: &SchemaAdmissionRequest) -> AdmissionDecision {
        AdmissionDecision {
            allowed: true,
            violations: vec![],
        }
    }
}
