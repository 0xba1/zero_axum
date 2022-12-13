use std::{net::TcpListener, sync::Arc};

use axum::{
    routing::{get, post},
    Extension, Router,
};
use hyper::Body;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceBuilder;
use tower_http::{
    request_id::MakeRequestUuid,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    ServiceBuilderExt,
};
use tracing::Level;

use crate::{
    configuration::{DatabaseSettings, Settings},
    email_client::EmailClient,
    routes::{confirm, health_check, subscribe},
};

pub struct Application {
    listener: TcpListener,
    router: Router<(), Body>,
}

impl Application {
    pub fn build(configuration: Settings) -> Result<Self, std::io::Error> {
        let db_pool = get_connection_pool(&configuration.database);

        let sender_email = configuration
            .email_client
            .sender()
            .expect("Invalid sender email sender");

        let timeout = configuration.email_client.timeout();

        let address = format!(
            "{}:{}",
            &configuration.application.host, &configuration.application.port
        );

        let email_client = EmailClient::new(
            configuration.email_client.base_url,
            sender_email,
            configuration.email_client.authorization_token,
            timeout,
        );

        let listener = TcpListener::bind(&address)?;
        tracing::debug!("Listening on {}", &address);
        let router = get_router(db_pool, email_client, configuration.application.base_url);

        Ok(Self { listener, router })
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    pub async fn run_until_stopped(self) -> hyper::Result<()> {
        axum::Server::from_tcp(self.listener)
            .expect("Could not use TCP listener")
            .serve(self.router.into_make_service())
            .await
    }
}

pub fn get_connection_pool(configuration: &DatabaseSettings) -> PgPool {
    PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy_with(configuration.with_db())
}

#[derive(Clone)]
pub struct ApplicationBaseUrl(pub String);

pub fn get_router(
    db_pool: PgPool,
    email_client: EmailClient,
    base_url: String,
) -> Router<(), Body> {
    Router::new()
        .route("/health_check", get(health_check))
        .route("/subscriptions", post(subscribe))
        .route("/subscriptions/confirm", get(confirm))
        .layer(Extension(email_client))
        .layer(Extension(ApplicationBaseUrl(base_url)))
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
        .with_state(Arc::new(db_pool))
}
