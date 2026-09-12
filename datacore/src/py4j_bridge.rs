use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveSparkApp {
    pub app_id: String,
    pub app_name: String,
    pub master: String,
    pub spark_user: String,
    pub impersonated_do_as_user: String,
    pub status: String,
    pub start_time_ms: i64,
    pub executor_count: u32,
    pub memory_per_executor_mb: u32,
    pub injected_krb_principal: String,
}

pub struct Py4jGatewayServer {
    port: u16,
    active_apps: Arc<RwLock<HashMap<String, ActiveSparkApp>>>,
}

impl Py4jGatewayServer {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            active_apps: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start_listener(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port)).await?;
        tracing::info!("Native Py4J Gateway Server listening on port {}", self.port);

        let apps_ref = self.active_apps.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let apps = apps_ref.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_py4j_connection(socket, apps).await {
                                tracing::debug!("Py4J connection from {} closed: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Py4J accept failed: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_py4j_connection(
        socket: tokio::net::TcpStream,
        _apps: Arc<RwLock<HashMap<String, ActiveSparkApp>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (reader, mut writer) = socket.into_split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = buf_reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                break;
            }

            let cmd = line.trim();
            if cmd.is_empty() {
                continue;
            }

            match cmd.chars().next() {
                Some('c') => {
                    let mut target = String::new();
                    let mut method = String::new();
                    buf_reader.read_line(&mut target).await?;
                    buf_reader.read_line(&mut method).await?;

                    let target = target.trim();
                    let method = method.trim();

                    let mut arg = String::new();
                    loop {
                        arg.clear();
                        buf_reader.read_line(&mut arg).await?;
                        if arg.trim() == "e" || arg.is_empty() {
                            break;
                        }
                    }

                    tracing::debug!("Py4J Invoke: target='{}' method='{}'", target, method);

                    if method == "getOrCreate" || method == "getSparkContext" {
                        writer.write_all(b"yv\n").await?;
                    } else if method == "version" {
                        writer.write_all(b"ys3.5.1\n").await?;
                    } else {
                        writer.write_all(b"yv\n").await?;
                    }
                    writer.flush().await?;
                }
                Some('r') => {
                    let mut class_name = String::new();
                    buf_reader.read_line(&mut class_name).await?;
                    let mut arg = String::new();
                    loop {
                        arg.clear();
                        buf_reader.read_line(&mut arg).await?;
                        if arg.trim() == "e" || arg.is_empty() {
                            break;
                        }
                    }
                    writer.write_all(b"yro_virtual_spark_obj\n").await?;
                    writer.flush().await?;
                }
                Some('m') => {
                    writer.write_all(b"yv\n").await?;
                    writer.flush().await?;
                }
                _ => {
                    writer.write_all(b"yv\n").await?;
                    writer.flush().await?;
                }
            }
        }

        Ok(())
    }

    pub async fn bootstrap_spark_session(
        &self,
        app_name: &str,
        master: &str,
        executors: u32,
        memory_mb: u32,
        krb_principal: &str,
        do_as_user: &str,
    ) -> Result<ActiveSparkApp, String> {
        let app_id = format!("app-{}-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"), &uuid::Uuid::new_v4().to_string()[..6]);
        let now_ms = chrono::Utc::now().timestamp_millis();

        let app = ActiveSparkApp {
            app_id: app_id.clone(),
            app_name: app_name.to_string(),
            master: master.to_string(),
            spark_user: "spark_service".to_string(),
            impersonated_do_as_user: do_as_user.to_string(),
            status: "RUNNING".to_string(),
            start_time_ms: now_ms,
            executor_count: executors,
            memory_per_executor_mb: memory_mb,
            injected_krb_principal: krb_principal.to_string(),
        };

        let mut apps = self.active_apps.write().await;
        apps.insert(app_id.clone(), app.clone());

        Ok(app)
    }

    pub async fn complete_app(&self, app_id: &str) -> Result<(), String> {
        let mut apps = self.active_apps.write().await;
        if let Some(app) = apps.get_mut(app_id) {
            app.status = "COMPLETED".to_string();
            Ok(())
        } else {
            Err(format!("Spark Application '{app_id}' not found"))
        }
    }

    pub async fn list_apps(&self) -> Vec<ActiveSparkApp> {
        let apps = self.active_apps.read().await;
        apps.values().cloned().collect()
    }
}
