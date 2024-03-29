use std::fmt::Display;

use axum::{extract::State, response::{Redirect, IntoResponse, Response, ErrorResponse}, Form};
use axum_flash::Flash;
use hyper::{StatusCode, header::LOCATION, Body};
use secrecy::Secret;

use crate::{routes::{ error_chain_fmt}, authentication::{AuthError, Credentials, validate_credentials}, startup::AppState, session_state::TypedSession,};

#[derive(serde::Deserialize)]
pub struct FormData {
    username: String,
    password: Secret<String>,
}

pub const USER_ID_KEY: &str = "user_id";

#[tracing::instrument(
    skip(form, app_state, flash), 
    fields(username=tracing::field::Empty, user_id=tracing::field::Empty)
)]
pub async fn login(mut session: TypedSession, flash: Flash, State(app_state): State<AppState>, Form(form): Form<FormData>, )
 -> Result<Redirect, ErrorResponse> {
    let credentials = Credentials {
        username: form.username,
        password: form.password,
    };
    
    match validate_credentials(credentials, &app_state.db_pool).await {
        Ok(user_id) => {
            tracing::Span::current()
            .record("user_id", &tracing::field::display(&user_id));

        session.renew().await;
        session.insert_user_id(user_id).await.map_err(|e| login_redirect(LoginError::UnexpectedError(e.into()), flash))?;
            Ok(Redirect::to("/admin/dashboard"))
        }
        Err(e) => {
            let e = match e {
                AuthError::InvalidCredentials(_) => LoginError::AuthError(e.into()),
                AuthError::UnexpectedError(_) => {
                    LoginError::UnexpectedError(e.into())
                },
            };
            // let query_string = format!(
            //     "error={}",
            //     urlencoding::Encoded::new(e.to_string())
            // );
            // let hmac_tag = {
            //     let mut mac = Hmac::<sha2::Sha256>::new_from_slice(
            //         secret.0.expose_secret().as_bytes()
            //     ).unwrap();
            //     mac.update(query_string.as_bytes());
            //     mac.finalize().into_bytes()
            // };
            Err(login_redirect(e, flash))
        }
    }

}

#[derive(thiserror::Error)]
pub enum LoginError {
    #[error("Authentication failed")]
    AuthError(#[source] anyhow::Error),
    #[error("Something went wrong")]
    UnexpectedError(#[from] anyhow::Error),
}

impl std::fmt::Debug for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}




#[derive(thiserror::Error)]
pub struct LoginErrorWithFlash {
    login_error: LoginError,
    cookie_flash: Flash,
}

impl LoginErrorWithFlash {
    fn new(login_error: LoginError, cookie_flash: Flash) -> Self {
        Self { login_error, cookie_flash }
    }
}
impl Display for LoginErrorWithFlash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.login_error, f)
    }
}

impl std::fmt::Debug for LoginErrorWithFlash{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.login_error, f)
    }
}



impl IntoResponse for LoginErrorWithFlash {
    fn into_response(self) -> Response {
       
        (
            self.cookie_flash.error(self.login_error.to_string()), 
            Redirect::to("/login"),
        ).into_response()
    }
}



impl IntoResponse for LoginError{
    fn into_response(self) -> Response {

        let mut response = Response::builder().status(StatusCode::SEE_OTHER).body(Body::empty()).unwrap();
        
        

        let headers = response.headers_mut();

        headers.insert(LOCATION, "/login".parse().unwrap());

        headers.insert("Set-Cookie", format!("_flash={self}; Max-Age=0").parse().unwrap());

        response.into_response()
        
    }
}

// Redirect to the login page with an error message.
fn login_redirect(e: LoginError, cookie_flash: Flash) -> ErrorResponse {
    (
        cookie_flash.error(e.to_string()), 
        Redirect::to("/login"),
    ).into()
}
