use std::collections::HashMap;
use async_trait::async_trait;
use tracing::info;

#[derive(Clone, Debug, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running,
    Success,
    Failed(String),
}

#[async_trait]
pub trait PipelineTask: Send + Sync {
    fn id(&self) -> &str;
    async fn execute(&self) -> Result<(), String>;
}

pub struct DagEngine {
    tasks: HashMap<String, Box<dyn PipelineTask>>,
    dependencies: HashMap<String, Vec<String>>,
}

impl DagEngine {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            dependencies: HashMap::new(),
        }
    }

    pub fn register_task(&mut self, task: Box<dyn PipelineTask>, upstream_deps: Vec<String>) {
        let task_id = task.id().to_string();
        self.tasks.insert(task_id.clone(), task);
        self.dependencies.insert(task_id, upstream_deps);
    }

    pub async fn run(&self) -> Result<(), String> {
        let mut task_states: HashMap<String, TaskStatus> = self
            .tasks
            .keys()
            .map(|k| (k.clone(), TaskStatus::Pending))
            .collect();

        while task_states.values().any(|s| *s == TaskStatus::Pending) {
            let ready_tasks: Vec<String> = task_states
                .iter()
                .filter(|(id, status)| {
                    if **status != TaskStatus::Pending {
                        return false;
                    }
                    let deps = &self.dependencies[*id];
                    deps.iter().all(|dep| task_states.get(dep) == Some(&TaskStatus::Success))
                })
                .map(|(id, _)| id.clone())
                .collect();

            if ready_tasks.is_empty() {
                return Err("Deadlock or circular dependency detected in DAG".into());
            }

            for task_id in ready_tasks {
                info!(task = %task_id, "Executing workflow node");
                task_states.insert(task_id.clone(), TaskStatus::Running);

                let task = &self.tasks[&task_id];
                match task.execute().await {
                    Ok(_) => {
                        info!(task = %task_id, "Node completed successfully");
                        task_states.insert(task_id, TaskStatus::Success);
                    }
                    Err(err) => {
                        task_states.insert(task_id.clone(), TaskStatus::Failed(err.clone()));
                        return Err(format!("Task {task_id} failed: {err}"));
                    }
                }
            }
        }
        Ok(())
    }
}
