use std::{sync::Arc, fmt::Display};

use axum::{extract::State, response::{Redirect, IntoResponse, Response}, Form, Extension};
use hmac::{Hmac, Mac};
use hyper::{StatusCode, Body, header::LOCATION};
use secrecy::{Secret, ExposeSecret};
use sqlx::PgPool;

use crate::{routes::{Credentials, validate_credentials, error_chain_fmt}, authentication::AuthError, startup::HmacSecret};

#[derive(serde::Deserialize)]
pub struct FormData {
    username: String,
    password: Secret<String>,
}

#[tracing::instrument(
    skip(form, pool, secret), 
    fields(username=tracing::field::Empty, user_id=tracing::field::Empty)
)]
pub async fn login(State(pool): State<Arc<PgPool>>, Extension(secret): Extension<HmacSecret>, Form(form): Form<FormData>, )
 -> Result<Redirect, LoginErrorWithHmacSecret> {
    let credentials = Credentials {
        username: form.username,
        password: form.password,
    };
    
    match validate_credentials(credentials, &pool).await {
        Ok(user_id) => {
            tracing::Span::current()
            .record("user_id", &tracing::field::display(&user_id));
            Ok(Redirect::to("/"))
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
            // Err(e)
            Err(LoginErrorWithHmacSecret::new(e, secret))
        }
    }

    // let user_id = validate_credentials(credentials, &pool)
    //     .await
    //     .map_err(|e| match e {
    //         AuthError::InvalidCredentials(_) => LoginError::AuthError(e.into()),
    //         AuthError::UnexpectedError(_) => LoginError::UnexpectedError(e.into()),
    //     })?;

    // tracing::Span::current().record("user_id", &tracing::field::display(&user_id));
    
    // Ok(Redirect::to("/")) 
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

impl LoginError {
    fn to_statuscode(&self) -> StatusCode {
        // match &self {
        //     LoginError::AuthError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        //     LoginError::UnexpectedError(_) => StatusCode::UNAUTHORIZED,
        // }
        StatusCode::SEE_OTHER
    }
}


#[derive(thiserror::Error)]
pub struct LoginErrorWithHmacSecret {
    login_error: LoginError,
    hmac_secret: HmacSecret,
}

impl LoginErrorWithHmacSecret {
    fn new(login_error: LoginError, hmac_secret: HmacSecret) -> Self {
        Self { login_error, hmac_secret }
    }
}
impl Display for LoginErrorWithHmacSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.login_error, f)
    }
}

impl std::fmt::Debug for LoginErrorWithHmacSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.login_error, f)
    }
}



impl IntoResponse for LoginErrorWithHmacSecret {
    fn into_response(self) -> Response {
        let status_code = self.login_error.to_statuscode();

        let query_string = format!("error={}", urlencoding::Encoded::new(self.login_error.to_string()));

     

        let hmac_tag = {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(self.hmac_secret.0.expose_secret().as_bytes()).unwrap();
            mac.update(query_string.as_bytes());
            mac.finalize().into_bytes()
        };

        let mut response = Response::builder().status(StatusCode::SEE_OTHER).body(Body::empty()).unwrap();

        let headers = response.headers_mut();

        // let encoded_error = urlencoding::Encoded::new(self.login_error.to_string());
        headers.insert(LOCATION, "/login".parse().unwrap());

        headers.insert("Set-Cookie", format!("_flash={}", self.login_error).parse().unwrap());

        (status_code, response).into_response()
        // (status_code, Redirect::to(&format!("/login?error={query_string}&tag={hmac_tag:x}"))).into_response()
        
    }
}

