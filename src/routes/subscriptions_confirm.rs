use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(serde::Deserialize)]
pub struct Parameters {
    pub subscription_token: String,
}

#[tracing::instrument(name = "Confirm a pending subscriber", skip(parameters))]
pub async fn confirm(
    Query(parameters): Query<Parameters>,
    State(pool): State<Arc<PgPool>>,
) -> StatusCode {
    let id = match get_subscriber_id_from_token(&pool, &parameters.subscription_token).await {
        Ok(id) => id,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    match id {
        None => StatusCode::UNAUTHORIZED,
        Some(subscriber_id) => {
            if confirm_subscriber(&pool, subscriber_id).await.is_err() {
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
            StatusCode::OK
        }
    }
}

#[tracing::instrument(name = "Mark a subscriber as confirmed", skip(pool, subscriber_id))]
pub async fn confirm_subscriber(pool: &PgPool, subscriber_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"UPDATE subscriptions SET status = 'confirmed' WHERE id = $1"#,
        subscriber_id
    )
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to execute query: {:?}", e);
        e
    })?;

    Ok(())
}

#[tracing::instrument(name = "Get subscriber_id from token", skip(pool, subscription_token))]
pub async fn get_subscriber_id_from_token(
    pool: &PgPool,
    subscription_token: &str,
) -> Result<Option<uuid::Uuid>, sqlx::Error> {
    let result = sqlx::query!(
        "SELECT  subscriber_id FROM subscription_tokens \
        WHERE subscription_token = $1",
        subscription_token
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to execute query: {:?}", e);
        e
    })?;

    Ok(result.map(|r| r.subscriber_id))
}
