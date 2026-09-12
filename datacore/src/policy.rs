use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SparkContainerRules {
    pub allowed_registries: Vec<String>,
    pub disallow_root: bool,
    pub max_cpu_cores: u32,
    pub max_memory_mb: u64,
    pub disallow_privileged: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IcebergSchemaRules {
    pub mandatory_fields: Vec<String>,
    pub disallowed_fields: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySpec {
    pub action: String,
    pub spark_container: Option<SparkContainerRules>,
    pub iceberg_schema: Option<IcebergSchemaRules>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeclarativePolicy {
    pub api_version: String,
    pub kind: String,
    pub metadata: PolicyMetadata,
    pub spec: PolicySpec,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparkJobAdmissionRequest {
    pub job_name: String,
    pub image: String,
    pub run_as_user: i64,
    pub privileged: bool,
    pub cpu_cores: u32,
    pub memory_mb: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchemaAdmissionRequest {
    pub table_name: String,
    pub field_names: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionDecision {
    pub allowed: bool,
    pub policy_name: String,
    pub action: String,
    pub violations: Vec<String>,
    pub evaluation_time_micros: u128,
}

pub struct AdmissionController {
    policies: Arc<RwLock<HashMap<String, DeclarativePolicy>>>,
}

impl AdmissionController {
    pub fn new() -> Self {
        let mut policies = HashMap::new();

        let spark_policy_yaml = r#"
apiVersion: datacore.security/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-spark-containers
spec:
  action: Enforce
  sparkContainer:
    allowedRegistries:
      - "registry.corp.internal"
      - "docker.io/apache"
    disallowRoot: true
    maxCpuCores: 16
    maxMemoryMb: 65536
    disallowPrivileged: true
"#;
        let spark_policy: DeclarativePolicy = serde_yaml::from_str(spark_policy_yaml).unwrap();
        policies.insert(spark_policy.metadata.name.clone(), spark_policy);

        let iceberg_policy_yaml = r#"
apiVersion: datacore.security/v1
kind: ClusterPolicy
metadata:
  name: iceberg-governance-audit-fields
spec:
  action: Enforce
  icebergSchema:
    mandatoryFields:
      - "event_id"
      - "timestamp"
    disallowedFields:
      - "raw_ssn"
      - "unmasked_credit_card"
"#;
        let iceberg_policy: DeclarativePolicy = serde_yaml::from_str(iceberg_policy_yaml).unwrap();
        policies.insert(iceberg_policy.metadata.name.clone(), iceberg_policy);

        Self {
            policies: Arc::new(RwLock::new(policies)),
        }
    }

    pub async fn validate_spark_job(&self, req: &SparkJobAdmissionRequest) -> AdmissionDecision {
        let start = std::time::Instant::now();
        let policies = self.policies.read().await;

        let mut violations = Vec::new();
        let mut enforced = false;
        let mut policy_name = "None".to_string();

        for policy in policies.values() {
            if let Some(rules) = &policy.spec.spark_container {
                policy_name = policy.metadata.name.clone();
                if policy.spec.action.eq_ignore_ascii_case("Enforce") {
                    enforced = true;
                }

                let image_allowed = rules.allowed_registries.iter().any(|reg| req.image.starts_with(reg));
                if !image_allowed {
                    violations.push(format!(
                        "Container image '{}' is not hosted on an allowed registry: {:?}",
                        req.image, rules.allowed_registries
                    ));
                }

                if rules.disallow_root && req.run_as_user <= 0 {
                    violations.push(format!(
                        "runAsUser must be > 0 (non-root). Found UID: {}",
                        req.run_as_user
                    ));
                }

                if rules.disallow_privileged && req.privileged {
                    violations.push("Privileged container execution is strictly disallowed".to_string());
                }

                if req.cpu_cores > rules.max_cpu_cores {
                    violations.push(format!(
                        "Requested CPU cores ({}) exceeds policy limit ({})",
                        req.cpu_cores, rules.max_cpu_cores
                    ));
                }
                if req.memory_mb > rules.max_memory_mb {
                    violations.push(format!(
                        "Requested memory ({} MB) exceeds policy limit ({} MB)",
                        req.memory_mb, rules.max_memory_mb
                    ));
                }
            }
        }

        let elapsed = start.elapsed().as_micros();
        let allowed = violations.is_empty() || !enforced;

        AdmissionDecision {
            allowed,
            policy_name,
            action: if enforced { "Enforce" } else { "Audit" }.to_string(),
            violations,
            evaluation_time_micros: elapsed,
        }
    }

    pub async fn validate_iceberg_schema(&self, req: &SchemaAdmissionRequest) -> AdmissionDecision {
        let start = std::time::Instant::now();
        let policies = self.policies.read().await;

        let mut violations = Vec::new();
        let mut enforced = false;
        let mut policy_name = "None".to_string();

        for policy in policies.values() {
            if let Some(rules) = &policy.spec.iceberg_schema {
                policy_name = policy.metadata.name.clone();
                if policy.spec.action.eq_ignore_ascii_case("Enforce") {
                    enforced = true;
                }

                for mandatory in &rules.mandatory_fields {
                    if !req.field_names.iter().any(|f| f.eq_ignore_ascii_case(mandatory)) {
                        violations.push(format!(
                            "Table schema is missing mandatory governance field: '{mandatory}'"
                        ));
                    }
                }

                for disallowed in &rules.disallowed_fields {
                    if req.field_names.iter().any(|f| f.eq_ignore_ascii_case(disallowed)) {
                        violations.push(format!(
                            "Schema contains unauthorized/PII field: '{disallowed}'"
                        ));
                    }
                }
            }
        }

        let elapsed = start.elapsed().as_micros();
        let allowed = violations.is_empty() || !enforced;

        AdmissionDecision {
            allowed,
            policy_name,
            action: if enforced { "Enforce" } else { "Audit" }.to_string(),
            violations,
            evaluation_time_micros: elapsed,
        }
    }

    pub async fn apply_policy_yaml(&self, yaml_content: &str) -> Result<DeclarativePolicy, String> {
        let policy: DeclarativePolicy = serde_yaml::from_str(yaml_content)
            .map_err(|e| format!("YAML parse error: {e}"))?;

        let mut policies = self.policies.write().await;
        policies.insert(policy.metadata.name.clone(), policy.clone());
        Ok(policy)
    }

    pub async fn list_policies_yaml(&self) -> Vec<String> {
        let policies = self.policies.read().await;
        policies
            .values()
            .map(|p| serde_yaml::to_string(p).unwrap_or_default())
            .collect()
    }
}
