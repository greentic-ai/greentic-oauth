use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;

#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, subject: &str, payload: &[u8]) -> Result<(), PublishError>;
}

#[derive(Debug, Error)]
pub enum PublishError {
    #[error("event dispatch failed: {0}")]
    Dispatch(String),
}

pub type SharedPublisher = Arc<dyn EventPublisher>;

pub struct NoopPublisher;

#[async_trait]
impl EventPublisher for NoopPublisher {
    async fn publish(&self, _subject: &str, _payload: &[u8]) -> Result<(), PublishError> {
        Ok(())
    }
}
