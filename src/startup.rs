use std::{net::TcpListener, sync::Arc};

use axum::{
    routing::{get, post},
    Router,
};
use sqlx::PgPool;
use tower::ServiceBuilder;
use tower_http::{
    request_id::MakeRequestUuid,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    ServiceBuilderExt,
};
use tracing::Level;

use crate::routes::{health_check, subscribe};

pub async fn run(listener: TcpListener, db_pool: PgPool) -> hyper::Result<()> {
    let app = Router::new()
        .route("/health_check", get(health_check))
        .route("/subscriptions", post(subscribe))
        .layer(
            // from https://docs.rs/tower-http/0.2.5/tower_http/request_id/index.html#using-trace
            ServiceBuilder::new()
                .set_x_request_id(MakeRequestUuid)
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(
                            DefaultMakeSpan::new()
                                .include_headers(true)
                                .level(Level::INFO),
                        )
                        .on_response(DefaultOnResponse::new().include_headers(true)),
                )
                .propagate_x_request_id(),
        )
        .with_state(Arc::new(db_pool));

    axum::Server::from_tcp(listener)
        .expect("Could not use TCP listener")
        .serve(app.into_make_service())
        .await
}
