use axum::response::{IntoResponse, Redirect, Response};
use hyper::StatusCode;

// Return an opaque 500 while preserving the error root's cause for logging.
pub fn e500<T>(e: T) -> Response
where
    T: std::fmt::Debug + std::fmt::Display + 'static,
{
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

pub fn see_other(location: &str) -> Response {
    Redirect::to(location).into_response()
}
