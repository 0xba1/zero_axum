use anyhow::Context;
use axum::{
    extract::State,
    response::{ErrorResponse, IntoResponse, Redirect, Response},
};
use hyper::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{session_state::TypedSession, startup::AppState, utils::e500};

pub async fn admin_dashboard(
    session: TypedSession,
    State(app_state): State<AppState>,
) -> Result<Response, ErrorResponse> {
    let username = if let Some(user_id) = session.get_user_id().await {
        get_username(user_id, &app_state.db_pool)
            .await
            .map_err(e500)?
    } else {
        return Ok(Redirect::to("/login").into_response());
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8">
<title>Admin dashboard</title>
</head>
<body>
<p>Welcome {username}!</p>

<p>Available actions:</p>
<ol>
<li><a href="/admin/password">Change password</a></li>
<li>
<form name="logoutForm" action="/admin/logout" method="post">
<input type="submit" value="Logout">
</form>
</li>
</ol>

</body>
</html>"#
        ))
        .unwrap()
        .into_response())
}

#[tracing::instrument(name = "Get username", skip(pool))]
pub async fn get_username(user_id: Uuid, pool: &PgPool) -> Result<String, anyhow::Error> {
    let row = sqlx::query!(
        r#"
SELECT username
FROM users
WHERE user_id = $1
"#,
        user_id,
    )
    .fetch_one(pool)
    .await
    .context("Failed to perform a query to retrieve a username.")?;
    Ok(row.username)
}
