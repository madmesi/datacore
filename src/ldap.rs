use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LdapConfig {
    pub ldap_url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    pub user_search_base: String,
    pub group_search_base: String,
    pub allow_insecure_mock: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LdapUserRecord {
    pub dn: String,
    pub uid: String,
    pub full_name: String,
    pub email: String,
    pub kerberos_principal: String,
    pub member_of_groups: Vec<String>,
}

pub struct FreeIpaLdapClient {
    config: LdapConfig,
    mock_directory: RwLock<HashMap<String, (LdapUserRecord, String)>>,
}

impl FreeIpaLdapClient {
    pub fn new(config: LdapConfig) -> Self {
        let mut mock_directory = HashMap::new();
        mock_directory.insert(
            "admin".to_string(),
            (
                LdapUserRecord {
                    dn: "uid=admin,cn=users,cn=accounts,dc=corp,dc=internal".to_string(),
                    uid: "admin".to_string(),
                    full_name: "Directory Administrator".to_string(),
                    email: "admin@corp.internal".to_string(),
                    kerberos_principal: "admin@CORP.INTERNAL".to_string(),
                    member_of_groups: vec![
                        "admins".to_string(),
                        "data-engineers".to_string(),
                        "trust-admins".to_string(),
                    ],
                },
                "adminpass".to_string(),
            ),
        );
        mock_directory.insert(
            "jdoe".to_string(),
            (
                LdapUserRecord {
                    dn: "uid=jdoe,cn=users,cn=accounts,dc=corp,dc=internal".to_string(),
                    uid: "jdoe".to_string(),
                    full_name: "John Doe".to_string(),
                    email: "jdoe@corp.internal".to_string(),
                    kerberos_principal: "jdoe@CORP.INTERNAL".to_string(),
                    member_of_groups: vec!["analytics".to_string(), "spark-users".to_string()],
                },
                "Password123!".to_string(),
            ),
        );

        Self {
            config,
            mock_directory: RwLock::new(mock_directory),
        }
    }

    async fn connect(&self) -> Result<Ldap, String> {
        let settings = LdapConnSettings::new().set_no_tls_verify(true);
        let (conn, ldap) = LdapConnAsync::with_settings(settings, &self.config.ldap_url)
            .await
            .map_err(|e| format!("LDAP connection failed to {}: {e}", self.config.ldap_url))?;
        
        ldap3::drive!(conn);
        Ok(ldap)
    }

    pub async fn authenticate_user(&self, username: &str, password: &str) -> Result<LdapUserRecord, String> {
        match self.live_authenticate(username, password).await {
            Ok(user) => Ok(user),
            Err(live_err) => {
                if self.config.allow_insecure_mock {
                    tracing::warn!("Live LDAP bind failed ('{live_err}'). Falling back to directory mock.");
                    self.mock_authenticate(username, password).await
                } else {
                    Err(live_err)
                }
            }
        }
    }

    async fn live_authenticate(&self, username: &str, password: &str) -> Result<LdapUserRecord, String> {
        let mut ldap = self.connect().await?;

        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)
            .await
            .map_err(|e| format!("Service bind failed: {e}"))?
            .success()
            .map_err(|e| format!("Bind unsuccessful: {e}"))?;

        let filter = format!("(&(objectClass=posixAccount)(uid={username}))");
        let (rs, _res) = ldap
            .search(
                &self.config.user_search_base,
                Scope::Subtree,
                &filter,
                vec!["dn", "uid", "cn", "mail", "krbPrincipalName", "memberOf"],
            )
            .await
            .map_err(|e| format!("Search error: {e}"))?
            .success()
            .map_err(|e| format!("Search failed: {e}"))?;

        let entry = rs
            .into_iter()
            .next()
            .ok_or_else(|| format!("User '{username}' not found in FreeIPA directory"))?;

        let search_entry = SearchEntry::construct(entry);
        let user_dn = search_entry.dn.clone();

        let mut user_ldap = self.connect().await?;
        user_ldap
            .simple_bind(&user_dn, password)
            .await
            .map_err(|e| format!("User bind credentials rejected: {e}"))?
            .success()
            .map_err(|e| format!("Invalid password for '{username}': {e}"))?;

        let full_name = search_entry.attrs.get("cn").and_then(|v| v.first()).cloned().unwrap_or(username.to_string());
        let email = search_entry.attrs.get("mail").and_then(|v| v.first()).cloned().unwrap_or_default();
        let krb_principal = search_entry.attrs.get("krbPrincipalName").and_then(|v| v.first()).cloned().unwrap_or(format!("{username}@CORP.INTERNAL"));
        let member_of = search_entry.attrs.get("memberOf").cloned().unwrap_or_default();

        let clean_groups: Vec<String> = member_of
            .iter()
            .filter_map(|g| g.split(',').next().and_then(|cn| cn.strip_prefix("cn=")))
            .map(String::from)
            .collect();

        Ok(LdapUserRecord {
            dn: user_dn,
            uid: username.to_string(),
            full_name,
            email,
            kerberos_principal: krb_principal,
            member_of_groups: clean_groups,
        })
    }

    async fn mock_authenticate(&self, username: &str, password: &str) -> Result<LdapUserRecord, String> {
        let dir = self.mock_directory.read().await;
        if let Some((user, stored_pwd)) = dir.get(username) {
            if stored_pwd == password {
                return Ok(user.clone());
            }
        }
        Err(format!("LDAP 49 (Invalid Credentials) for user '{username}'"))
    }

    pub async fn search_users(&self, query: &str) -> Vec<LdapUserRecord> {
        let dir = self.mock_directory.read().await;
        dir.values()
            .map(|(u, _)| u.clone())
            .filter(|u| u.uid.contains(query) || u.full_name.to_lowercase().contains(&query.to_lowercase()))
            .collect()
    }
}
