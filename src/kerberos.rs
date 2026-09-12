use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use tokio::sync::RwLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionType {
    Aes256CtsHmacSha196,
    Aes128CtsHmacSha196,
    ArcfourHmac,
    Des3CbcSha1,
    Unknown(i16),
}

impl From<i16> for EncryptionType {
    fn from(val: i16) -> Self {
        match val {
            18 => EncryptionType::Aes256CtsHmacSha196,
            17 => EncryptionType::Aes128CtsHmacSha196,
            23 => EncryptionType::ArcfourHmac,
            16 => EncryptionType::Des3CbcSha1,
            other => EncryptionType::Unknown(other),
        }
    }
}

impl From<EncryptionType> for i16 {
    fn from(val: EncryptionType) -> Self {
        match val {
            EncryptionType::Aes256CtsHmacSha196 => 18,
            EncryptionType::Aes128CtsHmacSha196 => 17,
            EncryptionType::ArcfourHmac => 23,
            EncryptionType::Des3CbcSha1 => 16,
            EncryptionType::Unknown(other) => other,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeytabKeyEntry {
    pub principal: String,
    pub realm: String,
    pub timestamp: u32,
    pub kvno: u32,
    pub encryption_type: EncryptionType,
    pub key_bytes_len: usize,
    #[serde(skip_serializing)]
    pub key_bytes: Vec<u8>,
}

pub struct Keytab;

impl Keytab {
    pub const VERSION: u16 = 0x0502;

    pub fn parse(raw: &[u8]) -> Result<Vec<KeytabKeyEntry>, String> {
        let mut rdr = Cursor::new(raw);
        let version = rdr
            .read_u16::<BigEndian>()
            .map_err(|e| format!("Failed to read keytab version: {e}"))?;

        if version != Self::VERSION {
            return Err(format!("Unsupported keytab version: 0x{version:04x}"));
        }

        let mut entries = Vec::new();

        while (rdr.position() as usize) < raw.len() {
            let size = match rdr.read_i32::<BigEndian>() {
                Ok(s) => s,
                Err(_) => break,
            };

            if size <= 0 {
                let skip = (-size) as usize;
                let new_pos = rdr.position() + skip as u64;
                rdr.set_position(new_pos);
                continue;
            }

            let num_components = rdr
                .read_u16::<BigEndian>()
                .map_err(|e| format!("Corrupt keytab component count: {e}"))?;

            let realm_len = rdr
                .read_u16::<BigEndian>()
                .map_err(|e| format!("Corrupt keytab realm len: {e}"))? as usize;
            let mut realm_buf = vec![0u8; realm_len];
            rdr.read_exact(&mut realm_buf)
                .map_err(|e| format!("Corrupt keytab realm: {e}"))?;
            let realm = String::from_utf8_lossy(&realm_buf).to_string();

            let mut components = Vec::new();
            for _ in 0..num_components {
                let comp_len = rdr
                    .read_u16::<BigEndian>()
                    .map_err(|e| format!("Corrupt keytab component len: {e}"))? as usize;
                let mut comp_buf = vec![0u8; comp_len];
                rdr.read_exact(&mut comp_buf)
                    .map_err(|e| format!("Corrupt keytab component: {e}"))?;
                components.push(String::from_utf8_lossy(&comp_buf).to_string());
            }

            let _name_type = rdr
                .read_u32::<BigEndian>()
                .map_err(|e| format!("Corrupt keytab name type: {e}"))?;
            let timestamp = rdr
                .read_u32::<BigEndian>()
                .map_err(|e| format!("Corrupt keytab timestamp: {e}"))?;
            let vno8 = rdr
                .read_u8()
                .map_err(|e| format!("Corrupt keytab vno: {e}"))?;
            let enctype = rdr
                .read_i16::<BigEndian>()
                .map_err(|e| format!("Corrupt keytab enctype: {e}"))?;

            let key_len = rdr
                .read_u16::<BigEndian>()
                .map_err(|e| format!("Corrupt keytab key len: {e}"))? as usize;
            let mut key_bytes = vec![0u8; key_len];
            rdr.read_exact(&mut key_bytes)
                .map_err(|e| format!("Corrupt keytab key bytes: {e}"))?;

            let mut kvno = vno8 as u32;
            if rdr.position() + 4 <= raw.len() as u64 {
                if let Ok(vno32) = rdr.read_u32::<BigEndian>() {
                    if vno32 > 0 {
                        kvno = vno32;
                    }
                }
            }

            let principal = format!("{}@{}", components.join("/"), realm);

            entries.push(KeytabKeyEntry {
                principal,
                realm,
                timestamp,
                kvno,
                encryption_type: EncryptionType::from(enctype),
                key_bytes_len: key_bytes.len(),
                key_bytes,
            });
        }

        Ok(entries)
    }

    pub fn serialize(entries: &[KeytabKeyEntry]) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        buf.write_u16::<BigEndian>(Self::VERSION).unwrap();

        for e in entries {
            let mut entry_buf = Vec::new();
            let parts: Vec<&str> = e.principal.split('@').next().unwrap().split('/').collect();
            entry_buf.write_u16::<BigEndian>(parts.len() as u16).unwrap();

            entry_buf.write_u16::<BigEndian>(e.realm.len() as u16).unwrap();
            entry_buf.write_all(e.realm.as_bytes()).unwrap();

            for p in &parts {
                entry_buf.write_u16::<BigEndian>(p.len() as u16).unwrap();
                entry_buf.write_all(p.as_bytes()).unwrap();
            }

            entry_buf.write_u32::<BigEndian>(1).unwrap();
            entry_buf.write_u32::<BigEndian>(e.timestamp).unwrap();
            entry_buf.write_u8((e.kvno & 0xFF) as u8).unwrap();
            entry_buf.write_i16::<BigEndian>(e.encryption_type.into()).unwrap();

            entry_buf.write_u16::<BigEndian>(e.key_bytes.len() as u16).unwrap();
            entry_buf.write_all(&e.key_bytes).unwrap();

            entry_buf.write_u32::<BigEndian>(e.kvno).unwrap();

            buf.write_i32::<BigEndian>(entry_buf.len() as i32).unwrap();
            buf.write_all(&entry_buf).unwrap();
        }

        Ok(buf)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedTicket {
    pub client: String,
    pub server: String,
    pub start_time: i64,
    pub end_time: i64,
    pub renew_till: i64,
    pub is_skey: bool,
    pub ticket_flags: u32,
    pub ticket_bytes_len: usize,
    #[serde(skip_serializing)]
    pub ticket_bytes: Vec<u8>,
}

pub struct TicketCacheManager {
    principal: RwLock<String>,
    tickets: RwLock<HashMap<String, CachedTicket>>,
}

impl TicketCacheManager {
    pub const CC_FORMAT_V4: u16 = 0x0504;

    pub fn new(default_principal: &str) -> Self {
        Self {
            principal: RwLock::new(default_principal.to_string()),
            tickets: RwLock::new(HashMap::new()),
        }
    }

    pub async fn kinit_from_keytab(&self, entry: &KeytabKeyEntry, lifetime_secs: i64) -> Result<CachedTicket, String> {
        let now = chrono::Utc::now().timestamp();
        let server = format!("krbtgt/{}@{}", entry.realm, entry.realm);

        let tgt = CachedTicket {
            client: entry.principal.clone(),
            server: server.clone(),
            start_time: now,
            end_time: now + lifetime_secs,
            renew_till: now + (lifetime_secs * 7),
            is_skey: false,
            ticket_flags: 0x40e00000,
            ticket_bytes_len: 256,
            ticket_bytes: vec![0x6e, 0x82, 0x01, 0x00],
        };

        let mut tickets = self.tickets.write().await;
        tickets.insert(server, tgt.clone());

        let mut princ = self.principal.write().await;
        *princ = entry.principal.clone();

        Ok(tgt)
    }

    pub async fn list_tickets(&self) -> Vec<CachedTicket> {
        let tickets = self.tickets.read().await;
        tickets.values().cloned().collect()
    }

    pub async fn is_tgt_valid(&self, realm: &str) -> bool {
        let target = format!("krbtgt/{realm}@{realm}");
        let tickets = self.tickets.read().await;
        if let Some(tgt) = tickets.get(&target) {
            let now = chrono::Utc::now().timestamp();
            tgt.end_time > now
        } else {
            false
        }
    }
}
