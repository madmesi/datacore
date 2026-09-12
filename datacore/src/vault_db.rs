use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DbRoleConfig {
    pub role_name: String,
    pub db_name: String,
    pub default_ttl_secs: i64,
    pub max_ttl_secs: i64,
    pub creation_statements: String,
    pub revocation_statements: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DynamicDbCredential {
    pub lease_id: String,
    pub username: String,
    pub password: String,
    pub role: String,
    pub db_name: String,
    pub issue_time: i64,
    pub expire_time: i64,
    pub ttl_secs: i64,
    pub renewable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimulatedPgUser {
    pub username: String,
    pub privileges: Vec<String>,
    pub valid_until: i64,
}

pub struct VaultDbEngine {
    roles: Arc<RwLock<HashMap<String, DbRoleConfig>>>,
    active_leases: Arc<RwLock<HashMap<String, DynamicDbCredential>>>,
    pg_roles_catalog: Arc<RwLock<HashMap<String, SimulatedPgUser>>>,
}

impl VaultDbEngine {
    pub fn new() -> Self {
        let mut roles = HashMap::new();

        roles.insert(
            "spark-readonly".to_string(),
            DbRoleConfig {
                role_name: "spark-readonly".to_string(),
                db_name: "analytics_warehouse".to_string(),
                default_ttl_secs: 300,
                max_ttl_secs: 3600,
                creation_statements: "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT CONNECT ON DATABASE analytics_warehouse TO \"{{name}}\"; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";".to_string(),
                revocation_statements: "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; REVOKE CONNECT ON DATABASE analytics_warehouse FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";".to_string(),
            },
        );

        roles.insert(
            "airflow-writer".to_string(),
            DbRoleConfig {
                role_name: "airflow-writer".to_string(),
                db_name: "analytics_warehouse".to_string(),
                default_ttl_secs: 600,
                max_ttl_secs: 7200,
                creation_statements: "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT ALL PRIVILEGES ON DATABASE analytics_warehouse TO \"{{name}}\";".to_string(),
                revocation_statements: "REVOKE ALL PRIVILEGES ON DATABASE analytics_warehouse FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";".to_string(),
            },
        );

        Self {
            roles: Arc::new(RwLock::new(roles)),
            active_leases: Arc::new(RwLock::new(HashMap::new())),
            pg_roles_catalog: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn generate_credentials(&self, role_name: &str, requested_ttl: Option<i64>) -> Result<DynamicDbCredential, String> {
        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| format!("Vault DB role '{role_name}' not configured"))?;

        let ttl = requested_ttl
            .unwrap_or(role.default_ttl_secs)
            .min(role.max_ttl_secs);

        let now = chrono::Utc::now().timestamp();
        let expire_time = now + ttl;

        let unique_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let db_user = format!("v-token-{}-{unique_id}", role_name.replace('-', "_"));
        let db_pass = format!("vPass_{}_!", uuid::Uuid::new_v4().to_string().replace('-', ""));
        let lease_id = format!("database/creds/{role_name}/{}", uuid::Uuid::new_v4());

        let mut catalog = self.pg_roles_catalog.write().await;
        catalog.insert(
            db_user.clone(),
            SimulatedPgUser {
                username: db_user.clone(),
                privileges: vec![format!("CONNECT ON {}", role.db_name), "SELECT ON ALL TABLES".to_string()],
                valid_until: expire_time,
            },
        );

        let cred = DynamicDbCredential {
            lease_id: lease_id.clone(),
            username: db_user,
            password: db_pass,
            role: role_name.to_string(),
            db_name: role.db_name.clone(),
            issue_time: now,
            expire_time,
            ttl_secs: ttl,
            renewable: true,
        };

        let mut leases = self.active_leases.write().await;
        leases.insert(lease_id, cred.clone());

        Ok(cred)
    }

    pub async fn revoke_lease(&self, lease_id: &str) -> Result<String, String> {
        let mut leases = self.active_leases.write().await;
        let cred = leases
            .remove(lease_id)
            .ok_or_else(|| format!("Lease ID '{lease_id}' not found or already revoked"))?;

        let mut catalog = self.pg_roles_catalog.write().await;
        catalog.remove(&cred.username);

        Ok(format!("Revoked lease '{lease_id}' and dropped PostgreSQL role '{}'", cred.username))
    }

    pub async fn purge_expired_leases(&self) -> Vec<String> {
        let now = chrono::Utc::now().timestamp();
        let mut leases = self.active_leases.write().await;
        let mut catalog = self.pg_roles_catalog.write().await;

        let mut expired_keys = Vec::new();

        for (lease_id, cred) in leases.iter() {
            if cred.expire_time <= now {
                expired_keys.push((lease_id.clone(), cred.username.clone()));
            }
        }

        let mut revoked = Vec::new();
        for (lease_id, username) in expired_keys {
            leases.remove(&lease_id);
            catalog.remove(&username);
            revoked.push(format!("Auto-expired lease '{lease_id}' for user '{username}'"));
        }

        revoked
    }

    pub async fn list_active_leases(&self) -> Vec<DynamicDbCredential> {
        let leases = self.active_leases.read().await;
        leases.values().cloned().collect()
    }

    pub async fn list_pg_roles(&self) -> Vec<SimulatedPgUser> {
        let catalog = self.pg_roles_catalog.read().await;
        catalog.values().cloned().collect()
    }
}
