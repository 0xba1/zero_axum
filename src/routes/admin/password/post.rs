use axum::extract::State;
use axum::http::StatusCode;
use axum::response::ErrorResponse;
use axum::response::IntoResponse;
use axum::response::Redirect;
use axum::response::Response;
use axum::Form;
use axum_flash::Flash;
use secrecy::ExposeSecret;
use secrecy::Secret;
use uuid::Uuid;

use crate::authentication::validate_credentials;
use crate::authentication::AuthError;
use crate::authentication::Credentials;
use crate::routes::admin::dashboard::get_username;
use crate::session_state::TypedSession;
use crate::startup::AppState;
use crate::utils::e500;
use crate::utils::see_other;

#[derive(serde::Deserialize)]
pub struct FormData {
    current_password: Secret<String>,
    new_password: Secret<String>,
    new_password_check: Secret<String>,
}

pub async fn change_password(
    State(app_state): State<AppState>,
    session: TypedSession,
    flash: Flash,
    Form(form): Form<FormData>,
) -> Result<Response, Response> {
    let user_id = session.get_user_id().await;
    if user_id.is_none() {
        return Ok(Redirect::to("/login").into_response());
    }
    let user_id = user_id.unwrap();

    if form.new_password.expose_secret().len() < 13 {
        let flash = flash.error("The new password should contain more than 12 characters.");
        return Ok((flash, Redirect::to("/admin/password")).into_response());
    }

    if form.new_password.expose_secret().len() > 127 {
        let flash = flash.error("The new password should have less than 128 characters.");
        return Ok((flash, Redirect::to("/admin/password")).into_response());
    }

    if form.new_password.expose_secret() != form.new_password_check.expose_secret() {
        let flash =
            flash.error("You entered two different new passwords - the field values must match.");
        return Ok((flash, Redirect::to("/admin/password")).into_response());
    }

    let username = get_username(user_id, &app_state.db_pool)
        .await
        .map_err(e500)?;

    let credentials = Credentials {
        username,
        password: form.current_password,
    };
    if let Err(e) = validate_credentials(credentials, &app_state.db_pool).await {
        return match e {
            AuthError::InvalidCredentials(_) => {
                let flash = flash.error("The current password is incorrect.");
                Ok((flash, see_other("/admin/password")).into_response())
            }
            AuthError::UnexpectedError(_) => Err(e500(e)),
        };
    }

    crate::authentication::change_password(user_id, form.new_password, &app_state.db_pool)
        .await
        .map_err(e500)?;
    let flash = flash.error("Your password has been changed.");
    Ok((flash, see_other("/admin/password")).into_response())
}
