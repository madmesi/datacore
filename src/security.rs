use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use crate::kerberos::{CachedTicket, EncryptionType, Keytab, KeytabKeyEntry, TicketCacheManager};
use crate::ldap::{FreeIpaLdapClient, LdapConfig};
use crate::policy::AdmissionController;
use crate::vault_db::VaultDbEngine;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Authentication failed for principal: {0}")]
    AuthFailed(String),
    #[error("Secret path '{0}' not found in vault engine")]
    VaultSecretMissing(String),
    #[error("Kyverno policy violation: {0}")]
    PolicyRejected(String),
    #[error("Kerberos error: {0}")]
    KrbError(String),
    #[error("FreeIPA LDAP error: {0}")]
    LdapError(String),
}

#[derive(Clone, Debug)]
pub struct IdentityContext {
    pub username: String,
    pub kerberos_principal: String,
    pub session_token: String,
    pub groups: Vec<String>,
    pub email: String,
}

pub struct SecurityKernel {
    vault_secrets: HashMap<String, String>,
    allowed_groups: Vec<String>,
    pub ticket_cache: Arc<TicketCacheManager>,
    pub ldap: Arc<FreeIpaLdapClient>,
    pub admission: Arc<AdmissionController>,
    pub vault_db: Arc<VaultDbEngine>,
}

impl SecurityKernel {
    pub fn new() -> Self {
        let mut vault_secrets = HashMap::new();

        let synthetic_keytab_entries = vec![KeytabKeyEntry {
            principal: "spark/analytics.cluster.local@CORP.INTERNAL".to_string(),
            realm: "CORP.INTERNAL".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u32,
            kvno: 2,
            encryption_type: EncryptionType::Aes256CtsHmacSha196,
            key_bytes_len: 32,
            key_bytes: vec![0x4a; 32],
        }];

        let keytab_bytes = Keytab::serialize(&synthetic_keytab_entries).unwrap();
        let keytab_hex = keytab_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        vault_secrets.insert("secret/data/spark/keytab_raw".to_string(), keytab_hex);
        vault_secrets.insert(
            "secret/data/hdfs/core-site".to_string(),
            "<configuration><property><name>hadoop.security.authentication</name><value>kerberos</value></property></configuration>".to_string(),
        );

        let default_principal = "spark/analytics.cluster.local@CORP.INTERNAL";
        let ticket_cache = Arc::new(TicketCacheManager::new(default_principal));

        let tc = ticket_cache.clone();
        let entry = synthetic_keytab_entries[0].clone();
        tokio::spawn(async move {
            let _ = tc.kinit_from_keytab(&entry, 36000).await;
        });

        let ldap_config = LdapConfig {
            ldap_url: "ldaps://ipa.corp.internal:636".to_string(),
            bind_dn: "uid=datacore_bind,cn=sysaccounts,cn=etc,dc=corp,dc=internal".to_string(),
            bind_password: "ServiceAccountSecretPassword".to_string(),
            base_dn: "dc=corp,dc=internal".to_string(),
            user_search_base: "cn=users,cn=accounts,dc=corp,dc=internal".to_string(),
            group_search_base: "cn=groups,cn=accounts,dc=corp,dc=internal".to_string(),
            allow_insecure_mock: true,
        };
        let ldap = Arc::new(FreeIpaLdapClient::new(ldap_config));
        let admission = Arc::new(AdmissionController::new());
        let vault_db = Arc::new(VaultDbEngine::new());

        Self {
            vault_secrets,
            allowed_groups: vec!["admins".to_string(), "data-engineers".to_string(), "analytics".to_string()],
            ticket_cache,
            ldap,
            admission,
            vault_db,
        }
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<IdentityContext, SecurityError> {
        let user_record = self
            .ldap
            .authenticate_user(username, password)
            .await
            .map_err(SecurityError::LdapError)?;

        let authorized = user_record
            .member_of_groups
            .iter()
            .any(|group| self.allowed_groups.contains(group));

        if !authorized {
            return Err(SecurityError::PolicyRejected(format!(
                "User '{}' belongs to groups {:?}, but none match cluster RBAC policies {:?}",
                username, user_record.member_of_groups, self.allowed_groups
            )));
        }

        Ok(IdentityContext {
            username: user_record.uid,
            kerberos_principal: user_record.kerberos_principal,
            session_token: uuid::Uuid::new_v4().to_string(),
            groups: user_record.member_of_groups,
            email: user_record.email,
        })
    }

    pub fn fetch_vault_secret(&self, path: &str) -> Result<String, SecurityError> {
        self.vault_secrets
            .get(path)
            .cloned()
            .ok_or_else(|| SecurityError::VaultSecretMissing(path.to_string()))
    }

    pub fn get_parsed_keytab(&self, path: &str) -> Result<Vec<KeytabKeyEntry>, SecurityError> {
        let hex_str = self.fetch_vault_secret(path)?;
        let bytes = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap_or(0))
            .collect::<Vec<u8>>();

        Keytab::parse(&bytes).map_err(SecurityError::KrbError)
    }

    pub async fn renew_tgt(&self) -> Result<CachedTicket, SecurityError> {
        let entries = self.get_parsed_keytab("secret/data/spark/keytab_raw")?;
        let entry = entries
            .first()
            .ok_or_else(|| SecurityError::KrbError("Keytab contains zero entries".into()))?;

        self.ticket_cache
            .kinit_from_keytab(entry, 43200)
            .await
            .map_err(SecurityError::KrbError)
    }
}
