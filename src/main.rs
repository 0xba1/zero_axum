use std::net::TcpListener;

use secrecy::ExposeSecret;
use sqlx::postgres::PgPoolOptions;
use zero_axum::{
    configuration::get_configuration,
    startup::run,
    telemetry::{get_subscriber, init_subscriber},
};

#[tokio::main]
async fn main() -> hyper::Result<()> {
    let subscriber = get_subscriber("zero_axum".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);

    let configuration = get_configuration().expect("Failed to read configuration");
    let connection_string = configuration.database.connection_string();

    let db_pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy(connection_string.expose_secret())
        .expect("Failed to connect to Postgres");
    let address = format!(
        "{}:{}",
        &configuration.application.host, &configuration.application.port
    );
    let listener = TcpListener::bind(&address).expect("Failed to bind random port");
    tracing::debug!("Listening on {}", &address);
    run(listener, db_pool).await
}
