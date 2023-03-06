use axum::http::Response;
use axum::http::StatusCode;

pub async fn home() -> Response<String> {
    Response::builder()
        .status(StatusCode::OK)
        .body(include_str!("home.html").to_string())
        .unwrap()
}
