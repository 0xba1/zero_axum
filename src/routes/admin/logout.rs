use axum::response::{IntoResponse, Response};
use axum_flash::Flash;

use crate::{session_state::TypedSession, utils::see_other};

pub async fn log_out(mut session: TypedSession, flash: Flash) -> Result<Response, Response> {
    if session.get_user_id().await.is_none() {
        Ok(see_other("/login"))
    } else {
        session.log_out().await;
        let flash = flash.info("You have successfully logged out.");
        Ok((flash, see_other("/login")).into_response())
    }
}
