use async_trait::async_trait;
use axum::{extract::FromRequestParts, http::request::Parts, Extension};
use axum_sessions::SessionHandle;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct TypedSession {
    session_handle: SessionHandle,
}

impl TypedSession {
    const USER_ID_KEY: &'static str = "user_id";

    pub async fn renew(&mut self) {
        self.session_handle.write().await.regenerate();
    }

    pub async fn insert_user_id(&mut self, user_id: Uuid) -> Result<(), serde_json::Error> {
        self.session_handle
            .write()
            .await
            .insert(Self::USER_ID_KEY, user_id)
    }

    pub async fn get_user_id(&self) -> Option<Uuid> {
        self.session_handle.read().await.get(Self::USER_ID_KEY)
    }

    pub async fn log_out(&mut self) {
        self.session_handle.write().await.destroy();
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for TypedSession
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Extension(session_handle): Extension<SessionHandle> =
            Extension::from_request_parts(parts, state)
                .await
                .expect("Session extension missing. Is the session layer installed?");

        Ok(Self { session_handle })
    }
}
