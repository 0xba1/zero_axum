use std::{net::TcpListener, sync::Arc};

use axum::{
    extract::FromRef,
    routing::{get, post},
    Extension, Router,
};
use axum_flash::Key;
use hyper::Body;
use secrecy::{ExposeSecret, Secret};
use sqlx::{postgres::PgPoolOptions, PgPool, Pool, Postgres};
use tower::ServiceBuilder;
use tower_http::{
    request_id::MakeRequestUuid,
    trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer},
    ServiceBuilderExt,
};
use tracing::Level;

use crate::{
    configuration::{DatabaseSettings, Settings},
    email_client::EmailClient,
    routes::{confirm, health_check, home, login, login_form, publish_newsletter, subscribe},
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
        tracing::info!("Listening on {}", &address);
        let router = get_router(
            db_pool,
            email_client,
            configuration.application.base_url,
            configuration.application.hmac_secret,
        );

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
    hmac_secret: Secret<String>,
) -> Router<(), Body> {
    let flash_config = axum_flash::Config::new(Key::from(hmac_secret.expose_secret().as_bytes()));
    let app_state = AppState {
        db_pool: Arc::new(db_pool),
        flash_config,
    };
    Router::new()
        .route("/", get(home))
        .route("/health_check", get(health_check))
        .route("/login", get(login_form))
        .route("/login", post(login))
        .route("/subscriptions", post(subscribe))
        .route("/subscriptions/confirm", get(confirm))
        .route("/newsletters", post(publish_newsletter))
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
                        .on_request(DefaultOnRequest::new())
                        .on_response(DefaultOnResponse::new().include_headers(true)),
                )
                .propagate_x_request_id(),
        )
        .with_state(app_state)
}

#[derive(Clone)]
pub struct HmacSecret(pub Secret<String>);

#[derive(Clone, Debug)]
pub struct AppState {
    pub db_pool: Arc<Pool<Postgres>>,
    flash_config: axum_flash::Config,
}

impl FromRef<AppState> for axum_flash::Config {
    fn from_ref(state: &AppState) -> axum_flash::Config {
        state.flash_config.clone()
    }
}
